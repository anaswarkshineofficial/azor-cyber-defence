"""Runs the AZOR Telegram reporting bot inside the dashboard web service.

The bot uses the same process and DATABASE_PATH as the FastAPI dashboard,
so reports submitted through Telegram are visible in the dashboard.
"""
import asyncio
import logging
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command, CommandStart
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext
from aiogram.types import Message, ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove
from app.db import init_db, create_report
from app.intelligence import validate_public_telegram_link

log = logging.getLogger("azor.telegram")

CATEGORIES = [
    "Non-consensual intimate content",
    "Suspected sexual deepfake",
    "Leaked private imagery",
    "Sexual content involving a suspected minor",
    "Other exploitation / sale activity",
]
TARGETS = ["Group", "Channel", "Bot", "Account"]

class ReportFlow(StatesGroup):
    category = State()
    target = State()
    link = State()
    description = State()

def keyboard(items):
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=item)] for item in items],
        resize_keyboard=True,
        one_time_keyboard=True
    )

async def launch_bot():
    from app.config import BOT_TOKEN
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN is missing")
    init_db()
    bot = Bot(BOT_TOKEN)
    dp = Dispatcher()

    @dp.message(CommandStart())
    async def start(message: Message, state: FSMContext):
        await state.clear()
        await message.answer(
            "Welcome to AZOR CYBER DEFENCE.\\n\\n"
            "Use /report to submit a concern about a Telegram group, channel, bot or account.\\n\\n"
            "Safety: Do NOT send intimate images/videos or material involving minors. "
            "Submit only a public Telegram link (if available) and a text description. "
            "Reports are allegations and require human review. We cannot guarantee removal.\\n\\n"
            "Use /cancel at any time to stop."
        )

    @dp.message(Command("report"))
    async def begin_report(message: Message, state: FSMContext):
        await state.clear()
        await state.set_state(ReportFlow.category)
        await message.answer("Choose the report category:", reply_markup=keyboard(CATEGORIES))

    @dp.message(Command("cancel"))
    async def cancel(message: Message, state: FSMContext):
        await state.clear()
        await message.answer("Report cancelled.", reply_markup=ReplyKeyboardRemove())

    @dp.message(ReportFlow.category)
    async def choose_category(message: Message, state: FSMContext):
        if message.text not in CATEGORIES:
            await message.answer("Please choose one of the listed categories.")
            return
        await state.update_data(category=message.text)
        await state.set_state(ReportFlow.target)
        await message.answer("What type of Telegram target is involved?", reply_markup=keyboard(TARGETS))

    @dp.message(ReportFlow.target)
    async def choose_target(message: Message, state: FSMContext):
        if message.text not in TARGETS:
            await message.answer("Please choose Group, Channel, Bot or Account.")
            return
        await state.update_data(target_type=message.text.lower())
        await state.set_state(ReportFlow.link)
        await message.answer(
            "Send the public Telegram link if you have one (for example, t.me/...). "
            "If there is no safe/public link, type NONE.",
            reply_markup=ReplyKeyboardRemove()
        )

    @dp.message(ReportFlow.link)
    async def get_link(message: Message, state: FSMContext):
        value = (message.text or "").strip()
        if not value:
            await message.answer("Please send a public link or type NONE.")
            return
        if value.upper() != "NONE" and not (
            value.startswith("https://t.me/") or value.startswith("http://t.me/")
            or value.startswith("t.me/")
        ):
            await message.answer("Please provide a t.me public link, or type NONE.")
            return
        await state.update_data(public_link="" if value.upper() == "NONE" else value)
        await state.set_state(ReportFlow.description)
        await message.answer(
            "Describe what you observed in text only. Include approximate dates if known. "
            "Do not upload, forward or link to intimate media."
        )

    @dp.message(ReportFlow.description)
    async def get_description(message: Message, state: FSMContext):
        description = (message.text or "").strip()
        if len(description) < 15:
            await message.answer("Please provide at least 15 characters of text description.")
            return
        if len(description) > 2000:
            await message.answer("Please keep the description under 2,000 characters.")
            return
        data = await state.get_data()
        report_id = create_report(
            reporter_id=message.from_user.id if message.from_user else None,
            category=data["category"],
            target_type=data["target_type"],
            public_link=data.get("public_link", ""),
            description=description
        )
        await state.clear()
        await message.answer(
            f"Your report has been recorded as case #{report_id}.\\n"
            "A human reviewer must verify it. Do not send intimate media or contact the reported account.\\n"
            "For urgent danger or suspected child sexual abuse material, contact the appropriate authorities "
            "and child-protection reporting service immediately.",
            reply_markup=ReplyKeyboardRemove()
        )

    @dp.message(F.photo | F.video | F.document | F.animation)
    async def reject_media(message: Message):
        await message.answer(
            "Media uploads are disabled. Please do not send or forward intimate images/videos "
            "or any material involving minors. Use /report and provide text-only details."
        )

    task = asyncio.create_task(dp.start_polling(bot), name="azor-telegram-polling")
    return task, bot
