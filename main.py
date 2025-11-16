#py file for main bot functionality
from library import telebot
from library import BOT_TOKEN
from function import parse_user_input, get_maclookup_info, get_chatgpt_analysis, get_ip_info, get_shodan_info, check_abuse_ipdb, get_mac_vendor, analyze_ports

bot = telebot.TeleBot(BOT_TOKEN)

active_users = set()

#start bot
@bot.message_handler(commands=['start'])
def start(message):
    active_users.add(message.chat.id)
    markup = telebot.types.ReplyKeyboardMarkup(resize_keyboard=True)
    btn1 = telebot.types.KeyboardButton("Hello!")
    markup.add(btn1)
    bot.send_message(message.chat.id, "Hello! I'm your cybersecurity assistant bot.", reply_markup=markup)

#main menu
@bot.message_handler(content_types=['text'])
def get_text_message(message):
    if message.text == "Hello!":
        markup = telebot.types.ReplyKeyboardMarkup(resize_keyboard=True)
        btn1 = telebot.types.KeyboardButton("Work")
        markup.add(btn1)
        bot.send_message(message.chat.id, "Select an action from the menu:", reply_markup=markup)

    elif message.text == "Work":
        bot.send_message(message.chat.id, "Give me the information you have about the device")
        bot.register_next_step_handler(message, work_bot)

    else:
        bot.send_message(message.chat.id, "I didn't understand you. Please use the menu buttons")


#functionality of work bot
def work_bot(message):
    clear_text = parse_user_input(message.text)
    bot.send_message(message.chat.id, f"Parsed Information:\nIPs: {clear_text['ips']}\nMACs: {clear_text['macs']}\nPorts: {clear_text['ports']}")

    bot.send_message(message.chat.id, "Give me time to think..")
    for ip in clear_text['ips']:
        ip_info = get_ip_info(ip)
        abuse_info = check_abuse_ipdb(ip)
        shodan_info = get_shodan_info(ip)
        bot.send_message(message.chat.id, f"IP Info for {ip}:\n{ip_info}\nAbuseIPDB Info:\n{abuse_info}\nShodan Info:\n{shodan_info}")

    for mac in clear_text['macs']:
        mac_info_vendor = get_mac_vendor(mac)
        mac_info_maclookup = get_maclookup_info(mac)
        bot.send_message(message.chat.id, f"MAC Vendor Info for {mac}:\n{mac_info_vendor}\nMAC Lookup Info:\n{mac_info_maclookup}")
    
    port_list = clear_text['ports']
    port_infos = analyze_ports(port_list)
    for port_info in port_infos:
        bot.send_message(message.chat.id, f"Port Info:\n{port_info}")

    bot.send_message(message.chat.id, "Received information, analyzing it..")
    analysis = get_chatgpt_analysis()
    bot.send_message(message.chat.id, f"Analysis from ChatGPT:\n{analysis}")

    bot.send_message(message.chat.id, "Analysis complete, review results")

#run bot
if __name__ == "__main__":
    print("Bot is running...")
    bot.polling(non_stop=True)