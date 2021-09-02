from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

file = "ningun archivo seleccionado"
currentPath = os.getcwd()

#Funcion para comenzar el cifrado o descifrado
def comenzar():
    if file == "ningun archivo seleccionado":
        print("No se selecciono archivo")
        messagebox.showerror(title="Error", message="No se ha seleccionado ningun archivo")
    else:
        print("La opcion es " + combo.get())
        print("El path del archivo es" + file)

        if combo.get() == "Cifrar": #Se cifra el texto
            archivo = open(file, "r") #Se lee el texto del archivo
            texto =  archivo.read()
            archivo.close()
            print("El texto es:\n" + texto)

            key = get_random_bytes(16) #Se genera la llave de 16 bytes
            archivo = open(currentPath+"\key.txt" , "wb") #Se guarda la llave en un archivo en bytes
            archivo.write(key)
            archivo.close()

            cipher = AES.new(key, AES.MODE_EAX) #Se especifica que cifrado se va a usar
            nonce = cipher.nonce
            print("nonce: ")
            print(nonce)
            textoCifrado, tag = cipher.encrypt_and_digest(str.encode(texto)) #El texto se convierte a bytes y se cifra 

            archivo = open(file+"_C" , "wb") #Se guarda el cifrado en un archivo de bytes
            archivo.write(nonce)
            archivo.write(textoCifrado)
            archivo.close()
            print("\nEl texto cifrado es:")
            print(textoCifrado)

        else: #Se descifra
            archivo = open(currentPath+"\key.txt", "rb") # Se lee la llave como bytes
            keyDesdeArchivo = archivo.read() 
            archivo.close()

            archivo = open(file, "rb") # Se lee el archivo como bytes
            nonce = archivo.read(16)
            textoCifrado = archivo.read()
            archivo.close()

            cipher = AES.new(keyDesdeArchivo, AES.MODE_EAX, nonce=nonce) #Se descifra con AES
            textoDescifrado = cipher.decrypt(textoCifrado)
            textoPlano = textoDescifrado.decode("utf-8", "ignore")
            print("El texto descrifrado es: \n" + textoPlano)

            archivo = open(file+"_D", "w")
            archivo.write(textoPlano)
            archivo.close()

#Funcion para seleccionar un archivo
def choose():
    global file
    file = filedialog.askopenfilename()
    fileLabel.configure(text=file)

#Elementos de la ventana
window = Tk()
window.title("Practica 0")
window.geometry("600x400")
window["bg"] = "#242424"

#Label
lbl = Label(window, text="Practica 0 - Martinez Fernando\n Cifrado AES \nSeleccione la opcion que desee", font=("Arial", 15))
lbl["bg"]= "#242424"
lbl["fg"] = "#ffffff"
lbl.place(x=160, y=20)

#Combobox
combo = ttk.Combobox(window, values=["Cifrar","Descifrar"],state="readonly")
combo.current(0)
combo.place(x =225,y = 120)

#Selector de archivos
fileButton = Button(window, text="Seleccionar archivo", command=choose)
fileButton.place(x=240, y=180)
fileButton["bg"] = "#26c6da"
fileLabel = Label(window, text=file, font=("Arial", 9), width=70)
fileLabel.place(x=55, y=220)
fileLabel["bg"]= "#242424"
fileLabel["fg"] = "#ffffff"
fileLabel.config(anchor=CENTER)

#Boton
btn = Button(window, text="Comenzar", command=comenzar)
btn["bg"] = "#26c6da"
btn.place(x=260, y=280)

window.mainloop()

