import wx
import os
import cryptography.hazmat.primitives.padding as pad
import cryptography.hazmat.primitives as hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import modes, algorithms, aead, Cipher


class MyWindow(wx.Frame):
    """"Janela contendo tudo"""

    __tiposAlteracoes = ('Criptografia', 'Hash')
    _Hash_para_escolher = ('MAC', 'SHA256')
    _Criptografia_para_escolher = ('AES_GCM', 'AES_CTR', 'AES_CBC', 'HMAC')
    __tipoAlteracaoEscolhida = ''
    __formulaHashOuCriptoEscolhida = ''

    def __init__(self, parent=None, title="Window"):
        size = (1024, 560)
        wx.Frame.__init__(self, parent=parent, title=title, size=size)
        self.SetMinSize(size)
        self.SetMaxSize(size)

        # Criando as Seções de layout da página
        self.mainSizer = wx.BoxSizer(wx.VERTICAL)
        self.SetSizer(self.mainSizer)
        self.tipoCriptografiaSizer = wx.BoxSizer(wx.HORIZONTAL)
        self.mainSizer.Add(self.tipoCriptografiaSizer, 1, wx.EXPAND)
        self.key_Iv_Sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.mainSizer.Add(self.key_Iv_Sizer, 1, wx.EXPAND)
        self.sizerMensagens = wx.BoxSizer(wx.HORIZONTAL)
        self.mainSizer.Add(self.sizerMensagens, 6, wx.EXPAND)
        self.mainSizer.AddSpacer(20)

        # Tipo de Criptografia
        self.tipoCriptografiaSizer.AddSpacer(20)
        titleLabel = wx.StaticText(self, label="Criptografia:", style=wx.BOLD)
        font = titleLabel.GetFont()
        font.PointSize += 10
        font = font.Bold()
        titleLabel.SetFont(font)
        self.tipoCriptografiaSizer.Add(titleLabel, 0, wx.ALIGN_CENTER_VERTICAL)
        self.tipoCriptografiaSizer.AddStretchSpacer()
        self.comboBoxTipoAlteracao = wx.ComboBox(self, size=(200, -1), choices=self.__tiposAlteracoes,
                                                 style=wx.CB_DROPDOWN)
        self.Bind(wx.EVT_COMBOBOX, self.eventoComboBoxTipoAlteracao, self.comboBoxTipoAlteracao)
        self.tipoCriptografiaSizer.Add(self.comboBoxTipoAlteracao, 0, wx.ALIGN_CENTER_VERTICAL, wx.ALIGN_RIGHT)
        self.tipoCriptografiaSizer.AddSpacer(10)

        self.comboBoxFormulaHashOuCripto = wx.ComboBox(self, choices=self._Criptografia_para_escolher,
                                                       size=(200, -1), style=wx.CB_DROPDOWN)
        self.Bind(wx.EVT_COMBOBOX, self.eventoComboBoxFormulaHashOuCripto, self.comboBoxFormulaHashOuCripto)
        self.tipoCriptografiaSizer.Add(self.comboBoxFormulaHashOuCripto, 0, wx.ALIGN_CENTER_VERTICAL, wx.ALIGN_RIGHT)
        self.tipoCriptografiaSizer.AddSpacer(20)

        # Chave e Iv
        self.key_Iv_Sizer.AddSpacer(60)
        self.buttonGerarChaveEIV = wx.Button(self, label="Gerar Chave e IV")
        self.key_Iv_Sizer.Add(self.buttonGerarChaveEIV, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddStretchSpacer()
        self.labelChave = wx.StaticText(self, label="Chave:", style=wx.BOLD)
        self.key_Iv_Sizer.Add(self.labelChave, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddSpacer(10)
        self.txtChave = wx.TextCtrl(self, size=(320, -1), name="Chave", style=wx.LC_SINGLE_SEL)
        self.key_Iv_Sizer.Add(self.txtChave, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddStretchSpacer()
        self.labelIV = wx.StaticText(self, label="IV/NOUNCE:", style=wx.BOLD)
        self.key_Iv_Sizer.Add(self.labelIV, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddSpacer(10)
        self.txtIV = wx.TextCtrl(self, size=(320, -1), name="IV", style=wx.LC_SINGLE_SEL)
        self.key_Iv_Sizer.Add(self.txtIV, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddStretchSpacer()
        self.key_Iv_Sizer.AddSpacer(20)

        # Encriptar e Decriptar
        self.sizerMensagens.AddSpacer(20)
        self.txtEntradaDados = wx.TextCtrl(self, size=(400, -1), name="Mensagem", style=wx.TE_MULTILINE)
        self.sizerMensagens.Add(self.txtEntradaDados, 1, wx.EXPAND)
        self.sizerMensagens.AddStretchSpacer(1)
        self.btnsCriptoEDecriptoSizer = wx.BoxSizer(wx.VERTICAL)
        self.btnsCriptoEDecriptoSizer.AddStretchSpacer(3)
        self.buttonCriptografar = wx.Button(self, label="Criptografar")
        self.btnsCriptoEDecriptoSizer.Add(self.buttonCriptografar, 0, wx.ALIGN_CENTER_HORIZONTAL, wx.ALIGN_TOP)
        self.btnsCriptoEDecriptoSizer.AddSpacer(20)
        self.buttonDecriptografar = wx.Button(self, label="Decriptografar")
        self.btnsCriptoEDecriptoSizer.Add(self.buttonDecriptografar, 0, wx.ALIGN_CENTER_HORIZONTAL, wx.ALIGN_BOTTOM)
        self.btnsCriptoEDecriptoSizer.AddStretchSpacer(3)
        self.sizerMensagens.Add(self.btnsCriptoEDecriptoSizer, 0, wx.ALIGN_CENTER)
        self.sizerMensagens.AddStretchSpacer(1)
        self.txtSaidaDados = wx.TextCtrl(self, size=(400, -1), name="MensagemCriptografada", style=wx.TE_MULTILINE)
        self.txtSaidaDados.SetCanFocus(False)
        self.txtSaidaDados.SetEditable(False)
        self.txtSaidaDados.SetBackgroundColour((150, 150, 150))
        self.sizerMensagens.Add(self.txtSaidaDados, 0, wx.EXPAND)
        self.sizerMensagens.AddSpacer(20)

        # Colocando as funções nos Botões
        self.Bind(wx.EVT_BUTTON, self.eventoGerarChaveBtn, self.buttonGerarChaveEIV)
        self.Bind(wx.EVT_BUTTON, self.eventoCriptografarBtn, self.buttonCriptografar)
        self.Bind(wx.EVT_BUTTON, self.eventoDecriptografarBtn, self.buttonDecriptografar)

        self.Show(True)

        # Define a escolha padrão da combo box e da trigger no evento
        self.comboBoxTipoAlteracao.SetSelection(0)
        self.comboBoxFormulaHashOuCripto.SetSelection(2)
        self.eventoComboBoxFormulaHashOuCripto(None)

    def eventoComboBoxTipoAlteracao(self, event):
        tipoAlteracaoEscolhida = self.comboBoxTipoAlteracao.GetValue()
        if tipoAlteracaoEscolhida in self.__tiposAlteracoes:
            self.__tipoAlteracaoEscolhida = tipoAlteracaoEscolhida
            nome_alteracao = '_' + str(tipoAlteracaoEscolhida) + '_para_escolher'
            listaFormulas = getattr(self, nome_alteracao)
            tempComboBoxFormulaHashOuCripto = wx.ComboBox(self, choices=listaFormulas, size=(200, -1), style=wx.CB_DROPDOWN)
            self.tipoCriptografiaSizer.Replace(self.comboBoxFormulaHashOuCripto, tempComboBoxFormulaHashOuCripto)
            self.tipoCriptografiaSizer.Layout()
            self.comboBoxFormulaHashOuCripto.Destroy()
            self.comboBoxFormulaHashOuCripto = tempComboBoxFormulaHashOuCripto
            self.Bind(wx.EVT_COMBOBOX, self.eventoComboBoxFormulaHashOuCripto, self.comboBoxFormulaHashOuCripto)

    def eventoComboBoxFormulaHashOuCripto(self, event):
        tipoCriptografia = self.comboBoxFormulaHashOuCripto.GetValue()
        if tipoCriptografia in self._Criptografia_para_escolher:
            self.__formulaHashOuCriptoEscolhida = tipoCriptografia
            nome_metodo = 'set_up_for_' + str(tipoCriptografia)
            method = getattr(self, nome_metodo)
            return method()
        else:
            self.criptografia_nao_suportada("Tipo de criptografia não suportado")

    def eventoGerarChaveBtn(self, event):
        try:
            tipoCriptografia = self.__formulaHashOuCriptoEscolhida
            if tipoCriptografia in self._Criptografia_para_escolher:
                nome_metodo = 'generate_key_for_' + str(tipoCriptografia)
                method = getattr(self, nome_metodo, self.criptografia_nao_suportada)
                return method()
        except ValueError as error:
            wx.MessageDialog(self, message=error.args[0], style=wx.ICON_ERROR, caption='Erro').ShowModal()

    def eventoCriptografarBtn(self, event):
        """Falta verificar se todos os campos estão preenchidos corretamente"""
        chave = bytes.fromhex(self.txtChave.GetValue())
        iv = bytes.fromhex(self.txtIV.GetValue())
        msg = self.txtEntradaDados.GetValue().encode()
        try:
            tipoCriptografia = self.__formulaHashOuCriptoEscolhida
            if tipoCriptografia in self._Criptografia_para_escolher:
                nome_metodo = 'encrypt_in_' + str(tipoCriptografia)
                method = getattr(self, nome_metodo, self.criptografia_nao_suportada)
                return method(chave, iv, msg)
        except ValueError as error:
            wx.MessageDialog(self, message=error.args[0], style=wx.ICON_ERROR, caption='Erro').ShowModal()

    def eventoDecriptografarBtn(self, event):
        """Falta verificar se todos os campos estão preenchidos corretamente"""
        chave = bytes.fromhex(self.txtChave.GetValue())
        iv = bytes.fromhex(self.txtIV.GetValue())
        try:
            msgEnc = bytes.fromhex(self.txtEntradaDados.GetValue())
            tipoCriptografia = self.__formulaHashOuCriptoEscolhida
            if tipoCriptografia in self._Criptografia_para_escolher:
                nome_metodo = 'decrypt_by_' + str(tipoCriptografia)
                method = getattr(self, nome_metodo, self.criptografia_nao_suportada)
                return method(chave, iv, msgEnc)
        except ValueError as error:
            wx.MessageDialog(self, message=error.args[0], style=wx.ICON_ERROR, caption='Erro').ShowModal()

    def set_up_for_AES_CTR(self):
        self.txtChave.SetEditable(True)
        self.txtChave.SetBackgroundColour((255, 255, 255))
        self.txtIV.SetEditable(True)
        self.txtIV.SetBackgroundColour((255, 255, 255))
        self.buttonGerarChaveEIV.Enable()
        self.buttonCriptografar.Enable()
        self.buttonDecriptografar.Enable()

    def generate_key_for_AES_CTR(self):
        self.txtChave.Clear()
        self.txtChave.WriteText(os.urandom(32).hex())
        self.txtIV.Clear()
        self.txtIV.WriteText(os.urandom(16).hex())

    def encrypt_in_AES_CTR(self, chave, iv, msg):
        encriptor = Cipher(algorithms.AES(chave), modes.CTR(iv), backend=default_backend()).encryptor()
        mensagemEncriptada = encriptor.update(msg) + encriptor.finalize()
        self.txtSaidaDados.Clear()
        self.txtSaidaDados.WriteText(mensagemEncriptada.hex())

    def decrypt_by_AES_CTR(self, chave, iv, msgEnc):
        decriptor = Cipher(algorithms.AES(chave), modes.CTR(iv), backend=default_backend()).decryptor()
        mensagemDecriptada = decriptor.update(msgEnc) + decriptor.finalize()
        self.txtSaidaDados.Clear()
        self.txtSaidaDados.WriteText(mensagemDecriptada.decode())

    def set_up_for_AES_GCM(self):
        self.txtChave.SetEditable(True)
        self.txtChave.SetBackgroundColour((255, 255, 255))
        self.txtIV.SetEditable(True)
        self.txtIV.SetBackgroundColour((255, 255, 255))
        self.buttonGerarChaveEIV.Enable()
        self.buttonCriptografar.Enable()
        self.buttonDecriptografar.Enable()

    def generate_key_for_AES_GCM(self):
        self.txtChave.Clear()
        self.txtChave.WriteText(aead.AESGCM.generate_key(256).hex())
        self.txtIV.Clear()
        self.txtIV.WriteText(os.urandom(16).hex())

    def encrypt_in_AES_GCM(self, chave, iv, msg):
        mensagemEncriptada = aead.AESGCM(chave).encrypt(iv, msg, None)
        self.txtSaidaDados.Clear()
        self.txtSaidaDados.WriteText(mensagemEncriptada.hex())

    def decrypt_by_AES_GCM(self, chave, iv, msgEnc):
        mensagemDecriptada = aead.AESGCM(chave).decrypt(iv, msgEnc, None)
        self.txtSaidaDados.Clear()
        self.txtSaidaDados.WriteText(mensagemDecriptada.decode())

    def set_up_for_AES_CBC(self):
        self.txtChave.SetEditable(True)
        self.txtChave.SetBackgroundColour((255, 255, 255))
        self.txtIV.SetEditable(True)
        self.txtIV.SetBackgroundColour((255, 255, 255))
        self.buttonGerarChaveEIV.Enable()
        self.buttonCriptografar.Enable()
        self.buttonDecriptografar.Enable()

    def generate_key_for_AES_CBC(self):
        self.txtChave.Clear()
        self.txtChave.WriteText(os.urandom(16).hex())
        self.txtIV.Clear()
        self.txtIV.WriteText(os.urandom(16).hex())

    def encrypt_in_AES_CBC(self, chave, iv, msg):
        padder = pad.PKCS7(algorithms.AES.block_size).padder()
        msg = padder.update(msg) + padder.finalize()
        encriptor = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend()).encryptor()
        mensagemEncriptada = encriptor.update(msg) + encriptor.finalize()
        self.txtSaidaDados.Clear()
        self.txtSaidaDados.WriteText(mensagemEncriptada.hex())

    def decrypt_by_AES_CBC(self, chave, iv, msgEnc):
        decriptor = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend()).decryptor()
        mensagemDecriptada = decriptor.update(msgEnc) + decriptor.finalize()
        unpadder = pad.PKCS7(algorithms.AES.block_size).unpadder()
        mensagemDecriptada = unpadder.update(mensagemDecriptada) + unpadder.finalize()
        self.txtSaidaDados.Clear()
        self.txtSaidaDados.WriteText(mensagemDecriptada.decode())

    def criptografia_nao_suportada(self, msg):
        wx.MessageDialog(self, message=msg, style=wx.ICON_ERROR).ShowModal()


class Cifrador(wx.App):
    def __init__(self):
        super().__init__(False)
        MyWindow(title="Cyfer")
        self.MainLoop()


Cifrador()
