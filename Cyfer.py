import wx
import os
import cryptography.hazmat.primitives.padding as pad
import cryptography.hazmat.primitives.hashes as hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import modes, algorithms, Cipher


class MyWindow(wx.Frame):
    """"Janela contendo tudo"""

    __tiposAlteracoes = ('Criptografia', 'Hash')
    _Hash_para_escolher = ('MD5', 'SHA1', 'SHA256', 'SHA512', 'SHA3_256', 'SHA3_512', 'SHA512_256')
    _Criptografia_para_escolher = (
        'AES_CTR', 'AES_CBC', 'AES_OFB', 'AES_CFB', 'AES_XTS', 'ChaCha20')
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
        titleLabel = wx.StaticText(self, label="Cyfer", style=wx.BOLD)
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
        self.key_Iv_Sizer.AddSpacer(20)
        self.key_Iv_Sizer.AddStretchSpacer()
        self.buttonGerarChaveEIV = wx.Button(self, label="Gerar Chave e IV")
        self.key_Iv_Sizer.Add(self.buttonGerarChaveEIV, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddSpacer(5)
        self.radio_btn_key_size = wx.RadioBox(self, choices=['128', '256'], majorDimension=1)
        self.key_Iv_Sizer.Add(self.radio_btn_key_size, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddStretchSpacer()
        self.labelChave = wx.StaticText(self, label="Chave:", style=wx.BOLD)
        self.key_Iv_Sizer.Add(self.labelChave, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddSpacer(5)
        self._txtChave = wx.TextCtrl(self, size=(320, -1), name="Chave", style=wx.LC_SINGLE_SEL)
        self.key_Iv_Sizer.Add(self._txtChave, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddStretchSpacer()
        self.labelIV = wx.StaticText(self, label="IV/NOUNCE:", style=wx.BOLD)
        self.key_Iv_Sizer.Add(self.labelIV, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddSpacer(5)
        self._txtIV = wx.TextCtrl(self, size=(320, -1), name="IV", style=wx.LC_SINGLE_SEL)
        self.key_Iv_Sizer.Add(self._txtIV, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddStretchSpacer()
        self.key_Iv_Sizer.AddSpacer(20)

        # Encriptar e Decriptar
        self.sizerMensagens.AddSpacer(20)
        self._txtEntradaDados = wx.TextCtrl(self, size=(400, -1), name="Mensagem", style=wx.TE_MULTILINE)
        self.sizerMensagens.Add(self._txtEntradaDados, 1, wx.EXPAND)
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
        self._txtSaidaDados = wx.TextCtrl(self, size=(400, -1), name="MensagemCriptografada", style=wx.TE_MULTILINE)
        self._txtSaidaDados.SetCanFocus(False)
        self._txtSaidaDados.SetEditable(False)
        self._txtSaidaDados.SetBackgroundColour((150, 150, 150))
        self.sizerMensagens.Add(self._txtSaidaDados, 0, wx.EXPAND)
        self.sizerMensagens.AddSpacer(20)

        # Colocando as funções nos Botões
        self.Bind(wx.EVT_BUTTON, self.eventoGerarChaveBtn, self.buttonGerarChaveEIV)
        self.Bind(wx.EVT_BUTTON, self.eventoCriptografarBtn, self.buttonCriptografar)
        self.Bind(wx.EVT_BUTTON, self.eventoDecriptografarBtn, self.buttonDecriptografar)

        self.Show(True)

        # Define a escolha padrão da combo box e da trigger no evento
        self.comboBoxTipoAlteracao.SetSelection(0)
        self.__tipoAlteracaoEscolhida = self.__tiposAlteracoes[0]
        self.comboBoxFormulaHashOuCripto.SetSelection(2)
        self.eventoComboBoxFormulaHashOuCripto(None)

    def eventoComboBoxTipoAlteracao(self, event):
        tipoAlteracaoEscolhida = self.comboBoxTipoAlteracao.GetValue()
        if tipoAlteracaoEscolhida in self.__tiposAlteracoes:
            self.__tipoAlteracaoEscolhida = tipoAlteracaoEscolhida
            nome_alteracao = '_' + str(tipoAlteracaoEscolhida) + '_para_escolher'
            listaFormulas = getattr(self, nome_alteracao)
            tempComboBoxFormulaHashOuCripto = wx.ComboBox(self, choices=listaFormulas, size=(200, -1),
                                                          style=wx.CB_DROPDOWN)
            self.tipoCriptografiaSizer.Replace(self.comboBoxFormulaHashOuCripto, tempComboBoxFormulaHashOuCripto)
            self.tipoCriptografiaSizer.Layout()
            self.comboBoxFormulaHashOuCripto.Destroy()
            self.comboBoxFormulaHashOuCripto = tempComboBoxFormulaHashOuCripto
            self.Bind(wx.EVT_COMBOBOX, self.eventoComboBoxFormulaHashOuCripto, self.comboBoxFormulaHashOuCripto)

            # Deixa editável somente os campos a serem utilizados
            nome_metodo = 'set_up_for_' + str(tipoAlteracaoEscolhida)
            method = getattr(self, nome_metodo)
            method()

    def eventoComboBoxFormulaHashOuCripto(self, event):
        """Precisa ser alterado para arrumar a função de geração de chave"""
        tipoCriptografia = self.comboBoxFormulaHashOuCripto.GetValue()
        nome_alteracao = '_' + str(self.__tipoAlteracaoEscolhida) + '_para_escolher'
        listaFormulas = getattr(self, nome_alteracao)
        if tipoCriptografia in listaFormulas:
            self.__formulaHashOuCriptoEscolhida = tipoCriptografia
        else:
            self.criptografia_nao_suportada("Tipo de criptografia não suportado")

    def eventoGerarChaveBtn(self, event):
        if self.__tipoAlteracaoEscolhida == 'Criptografia':
            if self.__formulaHashOuCriptoEscolhida in self._Criptografia_para_escolher:
                key_size = int((self.radio_btn_key_size.GetItemLabel(self.radio_btn_key_size.GetSelection()))) // 8
                self._txtChave.Clear()
                self._txtChave.WriteText(os.urandom(key_size).hex())
                self._txtIV.Clear()
                self._txtIV.WriteText(os.urandom(16).hex())

    def eventoCriptografarBtn(self, event):
        """Falta verificar se todos os campos estão preenchidos corretamente"""
        msg = self._txtEntradaDados.GetValue().encode()

        if self.__tipoAlteracaoEscolhida in self.__tiposAlteracoes:
            if self.__tipoAlteracaoEscolhida == 'Criptografia':
                self.criptografar(msg)
            elif self.__tipoAlteracaoEscolhida == 'Hash':
                self.gerarHash(msg)
        else:
            wx.MessageDialog(self, message="Selecione que tipo de alteração deseja fazer, Criptografia ou Hash.",
                             style=wx.ICON_ERROR, caption='Erro').ShowModal()

    def eventoDecriptografarBtn(self, event):
        """Falta verificar se todos os campos estão preenchidos corretamente"""
        if self.__tipoAlteracaoEscolhida in self.__tiposAlteracoes:
            if self.__tipoAlteracaoEscolhida == 'Criptografia':
                self.decriptografar()

    def set_up_for_Criptografia(self):
        self._txtChave.SetEditable(True)
        self._txtChave.SetBackgroundColour((255, 255, 255))
        self._txtIV.SetEditable(True)
        self._txtIV.SetBackgroundColour((255, 255, 255))
        self.buttonGerarChaveEIV.Enable()
        self.buttonCriptografar.Enable()
        self.buttonCriptografar.SetLabelText('Criptografar')
        self.buttonDecriptografar.Enable()
        self.comboBoxFormulaHashOuCripto.SetSelection(0)

    def set_up_for_Hash(self):
        self._txtChave.SetEditable(False)
        self._txtChave.SetBackgroundColour((150, 150, 150))
        self._txtIV.SetEditable(False)
        self._txtIV.SetBackgroundColour((150, 150, 150))
        self.buttonGerarChaveEIV.Disable()
        self.buttonCriptografar.Enable()
        self.buttonCriptografar.SetLabelText('Gerar Hash')
        self.buttonDecriptografar.Disable()
        self.comboBoxFormulaHashOuCripto.SetSelection(0)

    def criptografar(self, msg):
        chave = bytes.fromhex(self._txtChave.GetValue())
        iv = bytes.fromhex(self._txtIV.GetValue())
        cripto = self.__formulaHashOuCriptoEscolhida.split('_')
        algoritmo = getattr(algorithms, cripto[0])
        block_size = getattr(algoritmo, 'block_size', None)
        if len(cripto) > 1:
            modo = getattr(modes, cripto[1], None)
            modo = None if modo is None else modo(iv)
        else:
            modo = None
        if block_size is not None:
            padder = pad.PKCS7(block_size).padder()
            msg = padder.update(msg) + padder.finalize()
        if modo is not None:
            encriptor = Cipher(algoritmo(chave), modo, backend=default_backend()).encryptor()
        else:
            encriptor = Cipher(algoritmo(chave, iv), modo, backend=default_backend()).encryptor()
        mensagemEncriptada = encriptor.update(msg) + encriptor.finalize()
        self._txtSaidaDados.Clear()
        self._txtSaidaDados.WriteText(mensagemEncriptada.hex())

    def criptografia_nao_suportada(self, msg):
        wx.MessageDialog(self, message=msg, style=wx.ICON_ERROR).ShowModal()

    def gerarHash(self, msg):
        if self.__formulaHashOuCriptoEscolhida in self._Hash_para_escolher:
            hashEscolhido = getattr(hashes, self.__formulaHashOuCriptoEscolhida)
            digest = hashes.Hash(hashEscolhido(), backend=default_backend())
            digest.update(msg)
            hashedMsg = digest.finalize()
            self._txtSaidaDados.Clear()
            self._txtSaidaDados.WriteText(hashedMsg.hex())
        else:
            wx.MessageDialog(self, message="Formula hash escolhida não suportada.",
                             style=wx.ICON_ERROR, caption='Erro').ShowModal()

    def decriptografar(self):
        if self.__formulaHashOuCriptoEscolhida in self._Criptografia_para_escolher:
            cripto = self.__formulaHashOuCriptoEscolhida.split('_')
            algoritmo = getattr(algorithms, cripto[0])
            block_size = getattr(algoritmo, 'block_size', None)
            try:
                msgEnc = bytes.fromhex(self._txtEntradaDados.GetValue())
                chave = bytes.fromhex(self._txtChave.GetValue())
                iv = bytes.fromhex(self._txtIV.GetValue())
                if len(cripto) > 1:
                    modo = getattr(modes, cripto[1], None)
                    modo = None if modo is None else modo(iv)
                else:
                    modo = None
                if modo is not None:
                    decriptor = Cipher(algoritmo(chave), modo, backend=default_backend()).decryptor()
                else:
                    decriptor = Cipher(algoritmo(chave, iv), modo, backend=default_backend()).decryptor()
                mensagemDecriptada = decriptor.update(msgEnc) + decriptor.finalize()
                if block_size is not None:
                    unpadder = pad.PKCS7(algoritmo.block_size).unpadder()
                    mensagemDecriptada = unpadder.update(mensagemDecriptada) + unpadder.finalize()
                self._txtSaidaDados.Clear()
                self._txtSaidaDados.WriteText(mensagemDecriptada.decode())
            except ValueError as error:
                wx.MessageDialog(self, message=error.args[0], style=wx.ICON_ERROR, caption='Erro').ShowModal()


class Cifrador(wx.App):
    def __init__(self):
        super().__init__(False)
        MyWindow(title="Cyfer")
        self.MainLoop()


Cifrador()
