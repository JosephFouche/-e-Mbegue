#!/usr/bin/env python3
"""
Script de prueba para Alertapy Bot
Verifica que los comandos básicos funcionen correctamente.
"""

import asyncio
from telegram import Bot

#  el mismo token que estás usando en Alerta.py
TOKEN = "8142007072:AAF25V7ZJmbdaIEJyJ3ktwf-yXo2dz9OHwA"

async def main():
    bot = Bot(token=TOKEN)

    # 1️⃣ Verificar conexión con getMe
    me = await bot.get_me()
    print(f"✅ Bot conectado correctamente como: @{me.username}")

    # 2️⃣ Enviar un mensaje de prueba a tu propio chat
    # Usa tu user_id (lo podés obtener con @userinfobot en Telegram)
    chat_id = 5960000068
    msg = await bot.send_message(chat_id=chat_id, text="🔎 Prueba de conexión exitosa con Alertapy Bot.")
    print(f"📨 Mensaje enviado al chat {chat_id} (message_id={msg.message_id})")

if __name__ == "__main__":
    asyncio.run(main())
