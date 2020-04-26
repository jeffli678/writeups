import json
from mitmproxy import ctx
import pytesseract
import pyautogui
import time
import threading

i = 0

def recognize_char():
    print('recognizing ...')
    image = pyautogui.screenshot()
    image = image.crop((1540, 430, 1560, 465))
    # image.save('sc.png')
    txt = pytesseract.image_to_string(image, config='--psm 10 --oem 3 -c tessedit_char_whitelist=0123')
    val = int(txt, 10)
    if not val in [0, 1, 2, 3]:
        print('recognition failed!!!!!!!!!!!!!!!!')
        val = 0
    return val

def solve_and_inject(flow):
    global i 
    time.sleep(0.5)
    ans = recognize_char()
    sol = {'method' : 'answer', 'answer' : ans}
    print(sol)
    sol_str = json.dumps(sol)
    flow.inject_message(flow.server_conn, sol_str)
    i += 1
    print('solved: %d' % i)
    pass

def websocket_message(flow):

    # get the latest message
    message = flow.messages[-1]

    # was the message sent from the client or server?
    if message.from_client:
        ctx.log.info("Client sent a message: {}".format(message.content))
    else:
        ctx.log.info("Server sent a message: {}".format(message.content))

    if 'correctAnswer' in message.content:

        message.content = message.content.replace('questionText', 'replaced')
        message.content = message.content.replace('correctAnswer', 'questionText')

        t = threading.Thread(target = solve_and_inject, args = [flow])
        t.start()
