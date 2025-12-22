import logging
import os
import json
import argparse
import random
import concurrent.futures
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable

from coreApi.MainLogicApi import ApiClient
from coreApi.AiServiceClient import generate_article
from util.Config import ConfigManager
from util.MessagePush import MessagePusher
from util.HelperFunctions import desensitize_name, is_holiday
from util.FileUploader import upload_img

# 日志上下文支持
_log_ctx = threading.local()


class UserTagFormatter(logging.Formatter):
    def format(self, record):
        # 在格式化前添加 userTag 属性
        record.userTag = getattr(_log_ctx, "tag", "-")
        return super().format(record)


# 配置日志
_root_logger = logging.getLogger()
if not _root_logger.handlers:
    # 创建控制台处理器
    handler = logging.StreamHandler()
    formatter = UserTagFormatter(
        fmt="[%(asctime)s] %(name)s %(levelname)s [%(userTag)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    _root_logger.addHandler(handler)
    _root_logger.setLevel(logging.INFO)

logger = logging.getLogger(__name__)

USER_DIR = os.path.join(os.path.dirname(__file__), "user")


def perform_clock_in(api_client: ApiClient, config: ConfigManager) -> Dict[str, Any]:
    """执行打卡操作"""
    try:
        current_time = datetime.now()
        current_hour = current_time.hour

        # 确定打卡类型
        if current_hour < 12:
            checkin_type = "START"
            display_type = "上班"
        else:
            checkin_type = "END"
            display_type = "下班"

        # 检查配置：是否跳过节假日/自定义日期
        clock_in_mode = config.get_value("config.clockIn.mode")
        special_clock_in = config.get_value("config.clockIn.specialClockIn")

        should_skip = False
        skip_message = ""

        if clock_in_mode == "holiday" and is_holiday(current_time):
            if not special_clock_in:
                should_skip = True
                skip_message = "今天是休息日，已跳过打卡"
            else:
                checkin_type = "HOLIDAY"
                display_type = "休息/节假日"

        elif clock_in_mode == "custom":
            today_weekday = current_time.weekday() + 1
            custom_days = config.get_value("config.clockIn.customDays") or []
            if today_weekday not in custom_days:
                if not special_clock_in:
                    should_skip = True
                    skip_message = "今天不在设置打卡时间范围内，已跳过打卡"
                else:
                    checkin_type = "HOLIDAY"
                    display_type = "休息/节假日"

        if should_skip:
            return {
                "status": "skip",
                "message": skip_message,
                "task_type": "打卡",
            }

        last_checkin_info = api_client.get_checkin_info()

        # 检查是否已经打过卡
        if last_checkin_info and last_checkin_info.get("type") == checkin_type:
            create_time_str = last_checkin_info.get("createTime")
            if create_time_str:
                last_checkin_time = datetime.strptime(
                    create_time_str, "%Y-%m-%d %H:%M:%S"
                )
                if last_checkin_time.date() == current_time.date():
                    logger.info(f"今日 {display_type} 卡已打，无需重复打卡")
                    return {
                        "status": "skip",
                        "message": f"今日 {display_type} 卡已打，无需重复打卡",
                        "task_type": "打卡",
                    }

        user_name = desensitize_name(config.get_value("userInfo.nikeName"))
        logger.info(f"用户 {user_name} 开始 {display_type} 打卡")

        # 打卡图片和备注
        attachments = upload_img(
            api_client.get_upload_token(),
            config.get_value("userInfo.orgJson.snowFlakeId"),
            config.get_value("userInfo.userId"),
            config.get_value("config.clockIn.imageCount"),
        )

        description_list = config.get_value("config.clockIn.description")
        description = random.choice(description_list) if description_list else None

        # 设置打卡信息
        checkin_info = {
            "type": checkin_type,
            "lastDetailAddress": last_checkin_info.get("address"),
            "attachments": attachments or None,
            "description": description,
        }

        api_client.submit_clock_in(checkin_info)
        logger.info(f"用户 {user_name} {display_type} 打卡成功")

        return {
            "status": "success",
            "message": f"{display_type}打卡成功",
            "task_type": "打卡",
            "details": {
                "姓名": config.get_value("userInfo.nikeName"),
                "打卡类型": display_type,
                "打卡时间": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "打卡地点": config.get_value("config.clockIn.location.address"),
            },
        }
    except Exception as e:
        logger.error(f"打卡失败: {e}")
        return {"status": "fail", "message": f"打卡失败: {str(e)}", "task_type": "打卡"}


def _submit_report_common(
    api_client: ApiClient,
    config: ConfigManager,
    report_type: str,
    title_func: Callable[[int], str],
    check_time_func: Callable[[datetime], bool],
    get_submitted_func: Callable[[], Dict[str, Any]],
    paper_num_key: str,
    image_count_key: str,
    task_name: str,
    form_type: int,
) -> Dict[str, Any]:
    """通用日报/周报/月报提交逻辑"""

    # 映射 report_type 到 config key
    config_key_map = {"day": "daily", "week": "weekly", "month": "monthly"}
    config_key = config_key_map.get(report_type)

    if not config.get_value(f"config.reportSettings.{config_key}.enabled"):
        logger.info(f"用户未开启{task_name}功能，跳过")
        return {
            "status": "skip",
            "message": f"用户未开启{task_name}功能",
            "task_type": task_name,
        }

    current_time = datetime.now()

    # 检查提交时间
    if not check_time_func(current_time):
        logger.info(f"未到{task_name}提交时间")
        return {
            "status": "skip",
            "message": f"未到{task_name}提交时间",
            "task_type": task_name,
        }

    try:
        # 检查是否已提交
        submitted_reports_info = get_submitted_func()
        submitted_reports = submitted_reports_info.get("data", [])

        # 检查重复逻辑 (略有不同，由调用者保证 get_submitted_func 返回正确数据)
        # 对于日报：检查日期
        # 对于周报：检查 weeks 字段
        # 对于月报：检查 yearmonth 字段

        count = submitted_reports_info.get("flag", 0) + 1
        title = title_func(count)

        if submitted_reports:
            last_report = submitted_reports[0]
            should_skip = False

            if report_type == "day":
                last_time = datetime.strptime(
                    last_report["createTime"], "%Y-%m-%d %H:%M:%S"
                )
                if last_time.date() == current_time.date():
                    should_skip = True
            elif report_type == "week":
                # 周报 title 类似 "第X周周报"，或者 weeks 字段 "第X周"
                # API 返回的 weeks 字段比较可靠
                current_week_info = api_client.get_weeks_date()[0]
                current_week_str = f"第{count}周"  # 注意这里 count 是基于 flag+1，可能不准确如果重复提交
                # 更稳健的方式：检查 last_report 的 createTime 是否在当前周范围内
                # 但原代码是用 weeks 字符串匹配
                if last_report.get("weeks") == current_week_str:
                    should_skip = True
            elif report_type == "month":
                current_yearmonth = current_time.strftime("%Y-%m")
                if last_report.get("yearmonth") == current_yearmonth:
                    should_skip = True

            if should_skip:
                logger.info(f"本周期已经提交过{task_name}，跳过")
                return {
                    "status": "skip",
                    "message": f"本周期已经提交过{task_name}",
                    "task_type": task_name,
                }

        # 生成内容
        job_info = api_client.get_job_info()
        content = generate_article(
            config,
            title,
            job_info,
            config.get_value(paper_num_key),
        )

        # 上传图片
        attachments = upload_img(
            api_client.get_upload_token(),
            config.get_value("userInfo.orgJson.snowFlakeId"),
            config.get_value("userInfo.userId"),
            config.get_value(image_count_key),
        )

        report_info = {
            "title": title,
            "content": content,
            "attachments": attachments,
            "reportType": report_type,
            "jobId": job_info.get("jobId", None),
            "reportTime": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "formFieldDtoList": api_client.get_from_info(form_type),
        }

        # 特定类型的额外字段
        extra_details = {}
        if report_type == "week":
            current_week_info = api_client.get_weeks_date()[0]
            report_info["startTime"] = current_week_info.get("startTime")
            report_info["endTime"] = current_week_info.get("endTime")
            report_info["weeks"] = f"第{count}周"
            extra_details = {
                "开始时间": report_info["startTime"],
                "结束时间": report_info["endTime"],
            }
        elif report_type == "month":
            report_info["yearmonth"] = current_time.strftime("%Y-%m")
            extra_details = {"提交月份": report_info["yearmonth"]}

        api_client.submit_report(report_info)

        logger.info(f"{title}已提交")

        return {
            "status": "success",
            "message": f"{title}已提交",
            "task_type": task_name,
            "details": {
                "标题": title,
                "提交时间": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "附件": attachments,
                **extra_details,
            },
            "report_content": content,
        }

    except Exception as e:
        logger.error(f"{task_name}提交失败: {e}")
        return {
            "status": "fail",
            "message": f"{task_name}提交失败: {str(e)}",
            "task_type": task_name,
        }


def submit_daily_report(api_client: ApiClient, config: ConfigManager) -> Dict[str, Any]:
    """提交日报"""
    return _submit_report_common(
        api_client=api_client,
        config=config,
        report_type="day",
        title_func=lambda c: f"第{c}天日报",
        check_time_func=lambda t: t.hour >= 12,
        get_submitted_func=lambda: api_client.get_submitted_reports_info("day"),
        paper_num_key="planInfo.planPaper.dayPaperNum",
        image_count_key="config.reportSettings.daily.imageCount",
        task_name="日报提交",
        form_type=7,
    )


def submit_weekly_report(
    config: ConfigManager, api_client: ApiClient
) -> Dict[str, Any]:
    """提交周报"""
    submit_day = config.get_value("config.reportSettings.weekly.submitTime")

    def check_time(t: datetime) -> bool:
        # weekday() 返回 0-6 (周一-周日)，配置通常是 1-7
        return (t.weekday() + 1 == submit_day) and (t.hour >= 12)

    return _submit_report_common(
        api_client=api_client,
        config=config,
        report_type="week",
        title_func=lambda c: f"第{c}周周报",
        check_time_func=check_time,
        get_submitted_func=lambda: api_client.get_submitted_reports_info("week"),
        paper_num_key="planInfo.planPaper.weekPaperNum",
        image_count_key="config.reportSettings.weekly.imageCount",
        task_name="周报提交",
        form_type=8,
    )


def submit_monthly_report(
    config: ConfigManager, api_client: ApiClient
) -> Dict[str, Any]:
    """提交月报"""
    submit_day = config.get_value("config.reportSettings.monthly.submitTime")

    def check_time(t: datetime) -> bool:
        # 计算当月最后一天
        next_month = t.replace(day=28) + timedelta(days=4)
        last_day_of_month = (next_month - timedelta(days=next_month.day)).day
        target_day = min(submit_day, last_day_of_month)
        return (t.day == target_day) and (t.hour >= 12)

    return _submit_report_common(
        api_client=api_client,
        config=config,
        report_type="month",
        title_func=lambda c: f"第{c}月月报",
        check_time_func=check_time,
        get_submitted_func=lambda: api_client.get_submitted_reports_info("month"),
        paper_num_key="planInfo.planPaper.monthPaperNum",
        image_count_key="config.reportSettings.monthly.imageCount",
        task_name="月报提交",
        form_type=9,
    )


def run(config: ConfigManager) -> None:
    """执行所有任务"""
    # 设置日志上下文标签
    try:
        file_part = "ENV"
        path_attr = getattr(config, "_path", None)
        if path_attr:
            file_part = os.path.splitext(os.path.basename(str(path_attr)))[0]

        nickname = desensitize_name(config.get_value("userInfo.nikeName")) or "?"
        _log_ctx.tag = f"{file_part}|{nickname}"
    except Exception:
        _log_ctx.tag = "-"

    results: List[Dict[str, Any]] = []
    pusher = None

    try:
        pusher = MessagePusher(config.get_value("config.pushNotifications"))

        api_client = ApiClient(config)
        if not config.get_value("userInfo.token"):
            api_client.login()

        logger.info("获取用户信息成功")

        if config.get_value("userInfo.userType") == "teacher":
            logger.info("用户身份为教师，跳过计划信息检查")
        elif not config.get_value("planInfo.planId"):
            api_client.fetch_internship_plan()
            logger.info("已获取实习计划信息")

        logger.info(
            f"开始执行：{desensitize_name(config.get_value('userInfo.nikeName'))}"
        )

        results = [
            perform_clock_in(api_client, config),
            submit_daily_report(api_client, config),
            submit_weekly_report(config, api_client),
            submit_monthly_report(config, api_client),
        ]

    except Exception as e:
        error_message = f"执行任务时发生严重错误: {str(e)}"
        logger.error(error_message)
        results.append(
            {"status": "fail", "message": error_message, "task_type": "系统错误"}
        )
    finally:
        if pusher:
            try:
                pusher.push(results)
            except Exception as e:
                logger.error(f"消息推送失败: {e}")

        logger.info(
            f"执行结束：{desensitize_name(config.get_value('userInfo.nikeName'))}"
        )
        _log_ctx.tag = "-"


def execute_tasks(selected_files: Optional[List[str]] = None):
    """创建并执行任务"""
    _log_ctx.tag = "MAIN"
    logger.info("开始执行工学云任务")

    json_files = []
    try:
        if os.path.exists(USER_DIR):
            json_files = [f[:-5] for f in os.listdir(USER_DIR) if f.endswith(".json")]
            logger.info(f"发现 {len(json_files)} 个配置文件")
        else:
            logger.warning(f"用户目录不存在: {USER_DIR}")
    except OSError as e:
        logger.error(f"扫描配置文件目录失败: {e}")

    if selected_files:
        existing_files = set(selected_files) & set(json_files)
        missing_files = set(selected_files) - existing_files
        if missing_files:
            logger.error(f"以下配置文件未找到: {', '.join(missing_files)}")
        json_files = list(existing_files)

    user_configs = []
    user_env = os.getenv("USER")
    if user_env and user_env.strip():
        try:
            user_configs = json.loads(user_env)
            if not isinstance(user_configs, list):
                logger.error("环境变量 USER 必须包含 JSON 数组")
                user_configs = []
            else:
                logger.info(f"从环境变量中获取到 {len(user_configs)} 个配置")
        except json.JSONDecodeError as e:
            logger.error(f"USER 不是有效的JSON格式: {e}")

    if not json_files and not user_configs:
        logger.warning("未找到任何有效配置")
        return

    tasks = []

    for config_data in user_configs:
        try:
            tasks.append(ConfigManager(config=config_data))
        except Exception as e:
            logger.error(f"加载环境变量配置失败: {e}")

    for name in json_files:
        try:
            file_path = os.path.join(USER_DIR, f"{name}.json")
            tasks.append(ConfigManager(path=file_path))
        except Exception as e:
            logger.error(f"加载配置文件 {name} 失败: {e}")

    if not tasks:
        logger.error("没有成功创建任何任务")
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_task = {executor.submit(run, task): task for task in tasks}
        for future in concurrent.futures.as_completed(future_to_task):
            task = future_to_task[future]
            try:
                future.result()
            except Exception as e:
                logger.error(f"任务处理过程中发生错误: {e}")

    logger.info("工学云任务执行结束")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="运行工学云任务")
    parser.add_argument(
        "--file",
        type=str,
        nargs="+",
        help="指定要执行的配置文件名（不带路径和后缀），可以一次性指定多个",
    )
    args = parser.parse_args()
    execute_tasks(args.file)
