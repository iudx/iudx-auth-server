import sys
import time
import json
import telepot

telegram_apikey = open("telegram.apikey").read().strip()

bot = telepot.Bot(telegram_apikey)

def on_chat(msg):
	content_type, chat_type, chat_id = telepot.glance(msg)
	print('Chat Message:', content_type, chat_type, chat_id)

	if content_type == 'text':
		# TODO update the chat id of user
		pass	

def on_callback_query (msg):
	print ("Got token hash : ",msg)

	bot.sendMessage(msg["message"]["chat"]["id"], "ok")


bot.message_loop (
	{
		'chat'			: on_chat,
		'callback_query'	: on_callback_query
	},
	run_forever = True
)

print('Listening ...')
