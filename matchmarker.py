import random
import time
from tkinter import Tk,Button,DISABLED,messagebox
root=Tk()
root.title('Matchmarker')
root.resizable(width=False,height=False)
buttons={}
first=True
previousx=0
moves=0
pairs=0
previousy=0
button_symbols={}
adds=[u'\u2702',u'\u2705',u'\u2708',u'\u2709',u'\u270A',u'\u270B',
      u'\u270C',u'\u270F',u'\u2712',u'\u2714',u'\u2716',u'\u2728',
      u'\u2733',u'\u2734',u'\u2744',u'\u2747',u'\u274C',u'\u274E',
      u'\u2753',u'\u2754',u'\u2755',u'\u2757',u'\u2764',u'\u2795',
      u'\u2797',u'\u27A1',u'\u27B0',u'\u2756',u'\u2768',u'\u27E7']
def main():
    symbols=[]
    for add in adds:
        for i in range(2):
            symbols.append(add)
    random.shuffle(symbols)
    for x in range(10):
        for y in range(6):
            button=Button(command=lambda x=x,y=y:show_symbol(x,y),width=3,height=3)
            button.grid(column=x,row=y)
            buttons[x,y]=button
            button_symbols[x,y]=symbols.pop()
def show_symbol(x,y):
    global first,previousx,previousy,moves,pairs
    buttons[x,y]['text']=button_symbols[x,y]
    buttons[x,y].update_idletasks()
    if first:
        previousx=x
        previousy=y
        first=False
        moves+=1
    elif previousx!=x or previousy!=y:
        if buttons[previousx,previousy]['text']!=buttons[x,y]['text']:
            time.sleep(0.5)
            buttons[x,y]['text']=''
            buttons[previousx,previousy]['text']=''
        else:
            buttons[x,y]['command']=DISABLED
            buttons[previousx,previousy]['command']=DISABLED
            pairs+=1
            if pairs==len(buttons)/2:
                messagebox.showinfo('Match','移动次数：'+str(moves))
                root.destroy()
        first=True
root.mainloop()