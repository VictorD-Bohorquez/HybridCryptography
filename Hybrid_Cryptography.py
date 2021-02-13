import Crypto
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.Signature import PKCS1_v1_5

from tkinter import filedialog
from tkinter import *
from tkinter import Entry
from tkinter import messagebox
from Crypto.Cipher import DES
import hashlib 
import tkinter as tk

ventana=tk.Tk()
ventana.geometry('1200x650')
ventana.title("Practica hibrida")
ventana['bg'] ='#031929'
nombre="archivo"


#_____________________________________________________________________________________________________________________________________________________________________________________
def abrir_archivo():
    archivo_abierto=filedialog.askopenfilename(initialdir="C:/Users/DANIEL/Desktop/Crypto/final",title="Seleccione archivo",filetypes=(("txt files","*.txt"),("all files","*.*")))
    global nombre
    nombre = archivo_abierto

def obtenerNombre():
    aux=nombre
    return aux

def CreateKeys():
    random_generator = Random.new().read
    key=RSA.generate(1024,random_generator)
    private_key = open("Keys_ext/private_key.pem", "wb")
    private_key.write(key.exportKey("PEM"))
    private_key.close()
    public_key = open("Keys_ext/public_key.pem", "wb")
    public_key.write(key.publickey().exportKey("PEM"))
    public_key.close()  
    messagebox.showinfo("Llaves",message="Las llaves han sido creadas")

def LoadPublicKey():
    abrir_archivo()
    global pu_pathkey
    pu_pathkey=obtenerNombre()
    #label1=Label(ventana,text=pu_pathkey,bg='#031929',fg="white").place(x=230,y=100)

def LoadFileC():
    abrir_archivo()
    global ndoc
    ndoc=obtenerNombre()
    #label2=Label(ventana,text=ndoc,bg='#031929',fg="white").place(x=230,y=130)

def LoadPrivateKey():
    abrir_archivo()
    global pr_pathkey
    pr_pathkey=obtenerNombre()
    #print(pr_pathkey)
    #label3=Label(ventana,text=pr_pathkey,bg='#031929',fg="white").place(x=230,y=250)

def LoadFileD():
    abrir_archivo()
    global c_doc
    c_doc=obtenerNombre()
    #label3=Label(ventana,text=c_doc,bg='#031929',fg="white").place(x=230,y=280)

#Parte de cifrar el texto con AES
def Encrypt(p_text):
    key = Random.new().read(AES.block_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    #print(len(key))
    #print(len(iv))
    return key,iv,cipher.encrypt(p_text)
#Descifrar con AES
def Decrypt(key,iv,c_text):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    #print(cipher.decrypt(c_text))
    return cipher.decrypt(c_text)

def Cifrar():   
    #Abre el documento con el mensaje y lo manda a AES
    f = open (ndoc,'r')
    mensaje=f.read()
    f.close()
    mensaje=str.encode(mensaje)
    key_aes,iv,cif_aes=Encrypt(mensaje)
    #Carga la llave publica para RSA
    fk=open (pu_pathkey,"rb")
    key_pu=RSA.importKey(fk.read())
    key_pu=PKCS1_OAEP.new(key_pu)
    #Cifra la llave de AES en RSA
    key_aes_cif=key_pu.encrypt(key_aes)
    fk.close()
    #print('your encrypted text is : {}'.format(cifrado))
    doc_cif = ndoc.split(".")[0]+"_cf.txt"
    fc=open(doc_cif,"wb")
    fc.write(key_aes_cif)
    fc.write(b'<_1_>')
    fc.write(iv)
    fc.write(b'<_2_>')
    fc.write(cif_aes)
    fc.close()
    messagebox.showinfo("Cifrar",message="Se ha cifrado el mensaje")


def Descifrar():
    #Carga la llave privada
    f= open(pr_pathkey, "rb")
    private_key=RSA.import_key(f.read())
    private_key=PKCS1_OAEP.new(private_key)
    f.close()
    #Carga el documento cifrado
    fd=open(c_doc,"rb")
    texto_cifrado=fd.read()
    key_aes_cf,segunda_p=texto_cifrado.split(b'<_1_>',1)
    iv,mensaje_cif_aes=segunda_p.split(b'<_2_>')
    try:
        descif_key_aes=private_key.decrypt(key_aes_cf)
    except:
        messagebox.showinfo("Descifrar",message="Ciphertext with incorrect length.")
        e="                                                                                                                                                                      "
        label3=Label(ventana,text=e,bg='#031929',fg="white").place(x=230,y=280)
    fd.close()
    mensaje=Decrypt(descif_key_aes,iv,mensaje_cif_aes)
    mensaje=mensaje.decode()
    doc_desc = c_doc.split(".")[0]+"_desf.txt"
    fc=open(doc_desc,"w")
    fc.write(mensaje)
    fc.close()
    messagebox.showinfo("Descifrar",message="Se ha descifrado el mensaje")

    
def firmar(texto):
    try:
        f=open(pr_pathkey,"rb")
        key=RSA.importKey(f.read())
        f.close()
        aux=texto
        h = SHA1.new()
        h.update(aux.encode())
        signer = PKCS1_v1_5.new(key)
        sig = signer.sign(h)
        return sig
    except :
        messagebox.showerror("Firmar",message="La llave no es de tipo privada")


def verificar(text,firma):
    f=open (pu_pathkey,"rb")
    key=RSA.importKey(f.read())
    f.close()
    verifier = PKCS1_v1_5.new(key) 
    h= SHA1.new()
    h.update(text)
    verified = verifier.verify(h,firma)
    print(verified)
    return verified

def Firmard():   
    f = open (ndoc,'r')
    mensaje=f.read()
    f.close()
    #mensaje=str.encode(mensaje)
    firma=firmar(mensaje)  
    global sign 
    sign=firma
    doc_cif = ndoc.split(".")[0]+"_sign.txt"
    fc=open(doc_cif,"wb")
    fc.write(firma)
    fc.write(mensaje.encode())
    fc.close()
    messagebox.showinfo("Firmar",message="Se ha firmado el mensaje")
    

def Revisar():
    fd=open(c_doc,"rb")
    texto_cifrado=fd.read()
    fd.close()
    mensaje=texto_cifrado[128:len(texto_cifrado)]
    first_part=texto_cifrado[:128]
    if(verificar(mensaje,first_part)):
        messagebox.showinfo("Verificacion",message="El mensaje ha sido verificado")
    else:
        messagebox.showerror("Verificacion",message="El mensaje ha sido modificado o dañado")

def Cifrar_completo():
    Cifrar()
    Firmard()
    doc_cif = ndoc.split(".")[0]+"_cf.txt"
    fc=open(doc_cif,"rb")
    texto=fc.read()
    fc.close()
    fc=open(doc_cif,"wb")
    fc.write(texto)
    fc.write(b'<_3_>')
    fc.write(sign)
    fc.close
    
def Descifrar_completo():
    #Carga la llave privada
    f= open(pr_pathkey, "rb")
    private_key=RSA.import_key(f.read())
    private_key=PKCS1_OAEP.new(private_key)
    f.close()
    #Carga el documento cifrado
    fd=open(c_doc,"rb")
    texto_cifrado=fd.read()
    key_aes_cf,segunda_p=texto_cifrado.split(b'<_1_>',1)
    iv,tercera_p=segunda_p.split(b'<_2_>')
    mensaje_cif_aes,ver=tercera_p.split(b'<_3_>')
    try:
        descif_key_aes=private_key.decrypt(key_aes_cf)
    except:
        messagebox.showinfo("Descifrar",message="Ciphertext with incorrect length.")
        e="                                                                                                                                                                      "
        label3=Label(ventana,text=e,bg='#031929',fg="white").place(x=230,y=280)
    fd.close()
    mensaje=Decrypt(descif_key_aes,iv,mensaje_cif_aes)
    if (verificar(mensaje,ver)):
        messagebox.showinfo("Verificacion",message="El mensaje ha sido verificado")
        #Escribir el mensaje
        mensaje=mensaje.decode()
        doc_desc = c_doc.split(".")[0]+"_desf.txt"
        fc=open(doc_desc,"w")
        fc.write(mensaje)
        fc.close()
        messagebox.showinfo("Descifrar",message="Se ha descifrado el mensaje")
    else:
        messagebox.showinfo("Verificacion",message="El mensaje ha sido modificado")




#__________________________________________________________________________________________________________________________________________________________________________________________________________________________________
#INTERFAZ

Button(text="Crear llaves",bg='#06385b',highlightthickness=0,borderwidth=0,command=CreateKeys,fg="white",font=("Arial")).place(x=250,y=10)
#*******************************************************Parte de confidencialidad*****************************************************************
plabel_1=Label(ventana,text="CONFIDENCIALIDAD",bg='#031929',fg="white",font=("Arial",16)).place(x=10,y=25)
#Parte de cifrado
plabel1=Label(ventana,text="CIFRAR",bg='#031929',fg="white",font=("Arial",12)).place(x=10,y=75)
plabel2=Label(ventana,text="Llave publica:",bg='#031929',fg="white",font=("Arial",15)).place(x=40,y=100)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadPublicKey,fg="white",font=("Arial")).place(x=170,y=100)
plabel3=Label(ventana,text="Documento:",bg='#031929',fg="white",font=("Arial",15)).place(x=40,y=130)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadFileC,fg="white",font=("Arial")).place(x=170,y=130)
Button(text=" Cifrar ",bg='#06385b',highlightthickness=0,borderwidth=0,command=Cifrar,fg="white",font=("Arial")).place(x=45,y=165)

#Parte del descifrado

plabel4=Label(ventana,text="DESCIFRAR",bg='#031929',fg="white",font=("Arial",12)).place(x=10,y=200)
plabel5=Label(ventana,text="Llave privada:",bg='#031929',fg="white",font=("Arial",15)).place(x=40,y=230)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadPrivateKey,fg="white",font=("Arial")).place(x=170,y=230)
plabel6=Label(ventana,text="Documento:",bg='#031929',fg="white",font=("Arial",15)).place(x=40,y=260)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadFileD,fg="white",font=("Arial")).place(x=170,y=260)
Button(text=" Descifrar ",bg='#06385b',highlightthickness=0,borderwidth=0,command=Descifrar,fg="white",font=("Arial")).place(x=45,y=290)

#*******************************************************Parte de autentificacion*****************************************************************

plabel7=Label(ventana,text="AUTENTIFICACION",bg='#031929',fg="white",font=("Arial",16)).place(x=10,y=325)
#Parte de firma
plabel8=Label(ventana,text="FIRMAR",bg='#031929',fg="white",font=("Arial",12)).place(x=10,y=360)
plabel9=Label(ventana,text="Llave privada:",bg='#031929',fg="white",font=("Arial",15)).place(x=40,y=380)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadPrivateKey,fg="white",font=("Arial")).place(x=170,y=380)
plabel10=Label(ventana,text="Documento:",bg='#031929',fg="white",font=("Arial",15)).place(x=40,y=410)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadFileC,fg="white",font=("Arial")).place(x=170,y=410)
Button(text=" Firmar ",bg='#06385b',highlightthickness=0,borderwidth=0,command=Firmard,fg="white",font=("Arial")).place(x=45,y=440)

#Parte de verificacion
plabel11=Label(ventana,text="VERIFICAR",bg='#031929',fg="white",font=("Arial",12)).place(x=10,y=470)
plabel12=Label(ventana,text="Llave publica:",bg='#031929',fg="white",font=("Arial",15)).place(x=40,y=500)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadPublicKey,fg="white",font=("Arial")).place(x=170,y=500)
plabel13=Label(ventana,text="Documento:",bg='#031929',fg="white",font=("Arial",15)).place(x=40,y=530)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadFileD,fg="white",font=("Arial")).place(x=170,y=530)
Button(text=" Verificar ",bg='#06385b',highlightthickness=0,borderwidth=0,command=Revisar,fg="white",font=("Arial")).place(x=45,y=560)

#*******************************************************Parte completa*****************************************************************
#Parte cifrado completo
plabel_2=Label(ventana,text="CIF COMPLETO",bg='#031929',fg="white",font=("Arial",16)).place(x=650,y=25)
plabel_3=Label(ventana,text="Documento:",bg='#031929',fg="white",font=("Arial",15)).place(x=690,y=50)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadFileC,fg="white",font=("Arial")).place(x=820,y=50)
plabel_4=Label(ventana,text="Key Pub Ext:",bg='#031929',fg="white",font=("Arial",15)).place(x=690,y=80)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadPublicKey,fg="white",font=("Arial")).place(x=820,y=80)
plabel_5=Label(ventana,text="Key Priv Per:",bg='#031929',fg="white",font=("Arial",15)).place(x=690,y=110)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadPrivateKey,fg="white",font=("Arial")).place(x=820,y=110)
Button(text=" Cifrar ",bg='#06385b',highlightthickness=0,borderwidth=0,command=Cifrar_completo,fg="white",font=("Arial")).place(x=690,y=140)

#Parte descifrado completo
plabel_6=Label(ventana,text="DESF COMPLETO",bg='#031929',fg="white",font=("Arial",16)).place(x=650,y=180)
plabel_7=Label(ventana,text="Documento:",bg='#031929',fg="white",font=("Arial",15)).place(x=690,y=210)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadFileD,fg="white",font=("Arial")).place(x=820,y=210)
plabel_8=Label(ventana,text="Key Pub Ext:",bg='#031929',fg="white",font=("Arial",15)).place(x=690,y=240)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadPublicKey,fg="white",font=("Arial")).place(x=820,y=240)
plabel_9=Label(ventana,text="Key Priv Per:",bg='#031929',fg="white",font=("Arial",15)).place(x=690,y=270)
Button(text="Cargar",bg='#06385b',highlightthickness=0,borderwidth=0,command=LoadPrivateKey,fg="white",font=("Arial")).place(x=820,y=270)
Button(text=" Descifrar ",bg='#06385b',highlightthickness=0,borderwidth=0,command=Descifrar_completo,fg="white",font=("Arial")).place(x=690,y=300)

ventana.mainloop()