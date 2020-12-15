import wx
import os
import shelve
from app_base import BaseApp
import cryptography.exceptions
import cryptography.hazmat.primitives.padding as pad
import cryptography.hazmat.primitives.hashes as hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import modes, algorithms, Cipher, aead


class MyWindow(wx.Frame):
    """"Janela contendo tudo"""

    __tiposAlteracoes = (_('Criptografia'), _('Hash'), _('Hmac'))
    __tiposAlteracoes_default = ('Criptografia', 'Hash', 'Hmac')
    _Hash_para_escolher = ('MD5', 'SHA1', 'SHA256', 'SHA512', 'SHA3_256', 'SHA3_512', 'SHA512_256')
    _Criptografia_para_escolher = ('AES_CTR', 'AES_CBC', 'AES_GCM', 'AES_OFB', 'AES_CFB', 'AES_XTS', 'ChaCha20')
    _Hmac_para_escolher = ('HMAC-MD5', 'HMAC-SHA1', 'HMAC-SHA256', 'HMAC-SHA512', 'HMAC-SHA3_256', 'HMAC-SHA3_512')
    __tipoAlteracaoEscolhida = ''
    __formulaHashOuCriptoEscolhida = ''

    def __init__(self, parent=None, title="Cyfer"):
        size = (1024, 560)
        wx.Frame.__init__(self, parent=parent, title=title, size=size)
        self.SetMinSize(size)
        self.SetMaxSize(size)

        # Criando menu superior e bara de status
        self.menuBar = wx.MenuBar()

        self.menu = wx.Menu()
        sobre = self.menu.Append(wx.ID_ABOUT, _("Sobre"),
                                 _(" Informação sobre esse programa"))
        lingua = self.menu.Append(wx.ID_CONVERT, _("Língua"),
                                  _(" Mudar a língua do programa"))
        salvar = self.menu.Append(wx.ID_SAVE, _("Salvar"),
                                  _(" Salva as configurações atuais para facilitar a decriptografia."))
        abrir = self.menu.Append(wx.ID_OPEN, _("Abrir"),
                                 _("Carregar arquivo de configurações específico a partir do nome."))
        # pesquisar = self.menu.Append(wx.ID_OPEN, _("Pesquisar"),
        #                          _("Pesquisar arquivos disponíveis na pasta base."))

        self.menuBar.Append(self.menu, _("&Menu"))

        self.Bind(wx.EVT_MENU, self.sobre, sobre)
        self.Bind(wx.EVT_MENU, self.lingua, lingua)
        self.Bind(wx.EVT_MENU, self.salvar, salvar)
        self.Bind(wx.EVT_MENU, self.carregar, abrir)
        # self.Bind(wx.EVT_MENU, self.pesquisar, pesquisar)

        self.SetMenuBar(self.menuBar)
        self.CreateStatusBar()

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
        self.buttonGerarChaveEIV = wx.Button(self, label=_("Gerar Chave e IV"))
        self.key_Iv_Sizer.Add(self.buttonGerarChaveEIV, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddSpacer(5)
        self.radio_btn_key_size = wx.RadioBox(self, choices=['128', '256'], majorDimension=1)
        self.key_Iv_Sizer.Add(self.radio_btn_key_size, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddStretchSpacer()
        self.labelChave = wx.StaticText(self, label=_("Chave:"), style=wx.BOLD)
        self.key_Iv_Sizer.Add(self.labelChave, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddSpacer(5)
        self._txtChave = wx.TextCtrl(self, size=(320, -1), name="Chave", style=wx.LC_SINGLE_SEL)
        self.key_Iv_Sizer.Add(self._txtChave, 0, wx.ALIGN_CENTER_VERTICAL)
        self.key_Iv_Sizer.AddStretchSpacer()
        self.labelIV = wx.StaticText(self, label=_("IV/NOUNCE:"), style=wx.BOLD)
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
        self.buttonCriptografar = wx.Button(self, label=_("Criptografar"))
        self.btnsCriptoEDecriptoSizer.Add(self.buttonCriptografar, 0, wx.ALIGN_CENTER_HORIZONTAL, wx.ALIGN_TOP)
        self.btnsCriptoEDecriptoSizer.AddSpacer(20)
        self.buttonDecriptografar = wx.Button(self, label=_("Decriptografar"))
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
        self.__tipoAlteracaoEscolhida = self.__tiposAlteracoes_default[0]
        self.comboBoxFormulaHashOuCripto.SetSelection(2)
        self.eventoComboBoxFormulaHashOuCripto(None)

    def eventoComboBoxTipoAlteracao(self, event):
        tipoAlteracaoEscolhida = self.comboBoxTipoAlteracao.GetValue()
        if tipoAlteracaoEscolhida in self.__tiposAlteracoes:
            tipoAlteracaoEscolhida = self.__tiposAlteracoes_default[
                self.__tiposAlteracoes.index(tipoAlteracaoEscolhida)]
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
            self.eventoComboBoxFormulaHashOuCripto(None)

    def eventoComboBoxFormulaHashOuCripto(self, event):
        tipoCriptografia = self.comboBoxFormulaHashOuCripto.GetValue()
        nome_alteracao = '_' + str(self.__tipoAlteracaoEscolhida) + '_para_escolher'
        listaFormulas = getattr(self, nome_alteracao)
        if tipoCriptografia in listaFormulas:
            self.__formulaHashOuCriptoEscolhida = tipoCriptografia
        else:
            self.error_dialog(_("Tipo de criptografia não suportado"))

    def eventoGerarChaveBtn(self, event):
        if self.__tipoAlteracaoEscolhida == 'Criptografia':
            if self.__formulaHashOuCriptoEscolhida in self._Criptografia_para_escolher:
                key_size = int((self.radio_btn_key_size.GetItemLabel(self.radio_btn_key_size.GetSelection()))) // 8
                self._txtChave.Clear()
                self._txtChave.WriteText(os.urandom(key_size).hex())
                self._txtIV.Clear()
                self._txtIV.WriteText(os.urandom(16).hex())
        elif self.__tipoAlteracaoEscolhida == 'Hmac':
            if self.__formulaHashOuCriptoEscolhida in self._Hmac_para_escolher:
                key_size = int((self.radio_btn_key_size.GetItemLabel(self.radio_btn_key_size.GetSelection()))) // 8
                self._txtChave.Clear()
                self._txtChave.WriteText(os.urandom(key_size).hex())

    def eventoCriptografarBtn(self, event):
        """Falta verificar se todos os campos estão preenchidos corretamente"""
        msg = self._txtEntradaDados.GetValue().encode()

        if self.__tipoAlteracaoEscolhida in self.__tiposAlteracoes:
            if self.__tipoAlteracaoEscolhida == 'Criptografia':
                self.criptografar(msg)
            elif self.__tipoAlteracaoEscolhida == 'Hash':
                self.gerarHash(msg)
            elif self.__tipoAlteracaoEscolhida == 'Hmac':
                self.gerarHmac(msg)
        else:
            self.error_dialog(_("Selecione que tipo de alteração deseja fazer, Criptografia ou Hash."))

    def eventoDecriptografarBtn(self, event):
        """Falta verificar se todos os campos estão preenchidos corretamente"""
        if self.__tipoAlteracaoEscolhida in self.__tiposAlteracoes:
            if self.__tipoAlteracaoEscolhida == 'Criptografia':
                self.decriptografar()
            if self.__tipoAlteracaoEscolhida == 'Hmac':
                self.verificar()

    def set_up_for_Criptografia(self):
        self._txtChave.SetEditable(True)
        self._txtChave.SetBackgroundColour((255, 255, 255))
        self._txtIV.SetEditable(True)
        self._txtIV.SetBackgroundColour((255, 255, 255))
        self.buttonGerarChaveEIV.Enable()
        self.buttonCriptografar.Enable()
        self.buttonCriptografar.SetLabelText(_('Criptografar'))
        self.buttonDecriptografar.Enable()
        self.buttonDecriptografar.SetLabelText(_('Decriptografar'))
        self.comboBoxFormulaHashOuCripto.SetSelection(0)

    def set_up_for_Hash(self):
        self._txtChave.SetEditable(False)
        self._txtChave.SetBackgroundColour((150, 150, 150))
        self._txtIV.SetEditable(False)
        self._txtIV.SetBackgroundColour((150, 150, 150))
        self.buttonGerarChaveEIV.Disable()
        self.buttonCriptografar.Enable()
        self.buttonCriptografar.SetLabelText(_('Gerar Hash'))
        self.buttonDecriptografar.Disable()
        self.comboBoxFormulaHashOuCripto.SetSelection(0)

    def set_up_for_Hmac(self):
        self._txtChave.SetEditable(True)
        self._txtChave.SetBackgroundColour((255, 255, 255))
        self._txtIV.SetEditable(False)
        self._txtIV.SetBackgroundColour((150, 150, 150))
        self.buttonGerarChaveEIV.Enable()
        self.buttonCriptografar.Enable()
        self.buttonCriptografar.SetLabelText(_('Assinar'))
        self.buttonDecriptografar.Enable()
        self.buttonDecriptografar.SetLabelText(_('Verificar'))
        self.comboBoxFormulaHashOuCripto.SetSelection(0)

    def error_dialog(self, msg):
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
            self.error_dialog(_("Formula hash escolhida não suportada."))

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
        try:
            if modo is not None:
                encriptor = Cipher(algoritmo(chave), modo, backend=default_backend()).encryptor()
            else:
                encriptor = Cipher(algoritmo(chave, iv), modo, backend=default_backend()).encryptor()
            mensagemEncriptada = encriptor.update(msg) + encriptor.finalize()
            if modo is not None and cripto[1] == 'GCM':
                mensagemEncriptada += encriptor.tag
            self._txtSaidaDados.Clear()
            self._txtSaidaDados.WriteText(mensagemEncriptada.hex())
        except ValueError as error:
            self.error_dialog(error.args[0])

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
                    if cripto[1] == 'GCM':
                        tag = msgEnc[-16:]
                        msgEnc = msgEnc[0:-16]
                        modo = None if modo is None else modo(iv, tag)
                    else:
                        modo = None if modo is None else modo(iv)
                else:
                    modo = None
                if modo is not None:
                    decriptor = Cipher(algoritmo(chave), modo, backend=default_backend()).decryptor()
                else:
                    decriptor = Cipher(algoritmo(chave, iv), modo, backend=default_backend()).decryptor()
                mensagemDecriptada = decriptor.update(msgEnc) + decriptor.finalize()
                if block_size is not None:
                    try:
                        unpadder = pad.PKCS7(block_size).unpadder()
                        mensagemDecriptada = unpadder.update(mensagemDecriptada) + unpadder.finalize()
                    except:
                        pass
                self._txtSaidaDados.Clear()
                self._txtSaidaDados.WriteText(mensagemDecriptada.decode())
            except ValueError as error:
                self.error_dialog(error.args[0])

    def gerarHmac(self, msg):
        try:
            chave = bytes.fromhex(self._txtChave.GetValue())
            cripto = self.__formulaHashOuCriptoEscolhida.split('-')
            hashEscolhido = getattr(hashes, cripto[1])
            hmacGenerator = hmac.HMAC(chave, hashEscolhido(), backend=default_backend())
            hmacGenerator.update(msg)
            assinaturaHmac = hmacGenerator.finalize()
            self._txtSaidaDados.Clear()
            self._txtSaidaDados.WriteText(assinaturaHmac.hex())
        except ValueError as error:
            self.error_dialog(error.args[0])

    def verificar(self):
        try:
            msg = self._txtEntradaDados.GetValue().encode()
            chave = bytes.fromhex(self._txtChave.GetValue())
            cripto = self.__formulaHashOuCriptoEscolhida.split('-')
            dialog = wx.TextEntryDialog(self, _(
                'Cole a suposta assinatura para a mensagem adicionada anteriormente:'),
                                        caption=_('Verificar Assinatura'))
            dialog.ShowModal()
            if not dialog.GetValue() == '':
                assinatura = bytes.fromhex(dialog.GetValue())
                hashEscolhido = getattr(hashes, cripto[1])
                hmacGenerator = hmac.HMAC(chave, hashEscolhido(), backend=default_backend())
                hmacGenerator.update(msg)
                hmacGenerator.verify(assinatura)
                self._txtSaidaDados.Clear()
                self._txtSaidaDados.WriteText(
                    _('Mensagem autêntica.\nEla foi gerada por essa chave e não foi alterada.'))
                wx.MessageDialog(self, _('Mensagem verificada com Sucesso!'), style=wx.OK).ShowModal()
        except ValueError as error:
            self.error_dialog(error.args[0])
        except cryptography.exceptions.InvalidSignature as notValid:
            self.error_dialog(_("Mensagem não foi gerada por essa chave!"))

    def sobre(self, evt):
        wx.MessageDialog(self,
                         _(
                             """Esse programa serve para criptografar, decriptografar, gerar hashs e gerar ou verificar assinaturas Hmac.\n\n"""
                             """Com exceção das mensagens, que devem ser adicionadas como texto plano, todas as outras informações  devem estar em hexadecimal, incluindo chaves, iv, textos criptografados e assinaturas hmac.\n"""
                             """Na criptografia AES e no modo GCM a tag gerada é concatenada ao final do resultado da cifragem e deve ser colocado da mesma forma quando se quiser decifra-lo."""),
                         style=wx.OK_DEFAULT).ShowModal()

    def lingua(self, evt):
        dialog = wx.SingleChoiceDialog(self, _("Para qual língua você gostaria de mudar o programa?"),
                                       _("Mudar Língua"),
                                       choices=list(app.sup_languages), style=wx.OK | wx.CANCEL)
        if dialog.ShowModal() == wx.ID_OK:
            app.updateLanguage(dialog.StringSelection)
            rebuild(self)

    def salvar(self, evt):
        dados_para_salvar = self.__tipoAlteracaoEscolhida
        dados_para_salvar += ":" + self.__formulaHashOuCriptoEscolhida
        if self.__tipoAlteracaoEscolhida in self.__tiposAlteracoes:
            if self.__tipoAlteracaoEscolhida == 'Criptografia':
                dados_para_salvar += ":" + self._txtChave.GetValue()
                dados_para_salvar += ":" + self._txtIV.GetValue()
                dados_para_salvar += ":" + self._txtEntradaDados.GetValue()
            elif self.__tipoAlteracaoEscolhida == 'Hmac':
                dados_para_salvar += ":" + self._txtChave.GetValue()
                dados_para_salvar += ":" + self._txtEntradaDados.GetValue()

            dialogNome = wx.TextEntryDialog(self, _('Escolha um nome para o arquivo:'),
                                            caption=_('Salvar Configurações de Criptografia'))
            dialogNome.ShowModal()
            dialogSenha = wx.TextEntryDialog(self,
                                             _(
                                                 'Entre uma senha para criptografar essas configurações, ela será necessária '
                                                 'para carregar essas informações mais tarde:'),
                                             caption=_('Salvar configurações de Criptografia'))
            dialogSenha.ShowModal()
            nome = dialogNome.GetValue()
            senha = dialogSenha.GetValue()
            if senha is not '' or None:
                salt = os.urandom(32)
                senha = senha.encode()
                dados_para_salvar = dados_para_salvar.encode()
                chave = PBKDF2HMAC(algorithm=hashes.SHA3_256, length=32, salt=salt, iterations=1000000,
                                   backend=default_backend()).derive(senha)
                nounce = os.urandom(16)
                aesgcm = aead.AESGCM(chave)
                dados_criptografados = aesgcm.encrypt(nounce, dados_para_salvar, None)
                dados_para_salvar = salt + dados_criptografados + nounce
                arquivo = shelve.open(nome)
                arquivo['cript'] = dados_para_salvar
                arquivo.close()

    def carregar(self, evt):
        dialogNome = wx.TextEntryDialog(self, _('Digite o nome do arquivo que deseja abrir:'),
                                        caption=_('Carregar Configurações de Criptografia'))
        dialogNome.ShowModal()
        nome = dialogNome.GetValue()
        if nome is not '':
            arq = shelve.open(nome)
            try:
                dados = arq['cript']
                salt = dados[:32]
                nounce = dados[-16:]
                dados = dados[32:len(dados) - 16]
                dialogSenha = wx.TextEntryDialog(self,
                                                 _('Entre a senha para decriptografar essas configurações:'),
                                                 caption=_('Carregar configurações de Criptografia'))
                dialogSenha.ShowModal()
                senha = dialogSenha.GetValue().encode()
                chave = PBKDF2HMAC(algorithm=hashes.SHA3_256, length=32, salt=salt, iterations=1000000,
                                   backend=default_backend()).derive(senha)
                dados_decriptografados = aead.AESGCM(chave).decrypt(nounce, dados, None)
                dados_separados = dados_decriptografados.decode().split(':')
                if dados_separados[0] == 'Criptografia':
                    self.comboBoxTipoAlteracao.SetSelection(0)
                    self.eventoComboBoxTipoAlteracao(None)
                    self.comboBoxFormulaHashOuCripto.SetSelection(
                        self._Criptografia_para_escolher.index(dados_separados[1]))
                    self.eventoComboBoxFormulaHashOuCripto(None)
                    self._txtChave.Clear()
                    self._txtChave.WriteText(dados_separados[2])
                    self._txtIV.Clear()
                    self._txtIV.WriteText(dados_separados[3])
                    self._txtEntradaDados.Clear()
                    self._txtEntradaDados.WriteText(dados_separados[4])
                elif dados_separados[0] == 'Hmac':
                    self.comboBoxTipoAlteracao.SetSelection(2)
                    self.eventoComboBoxTipoAlteracao(None)
                    self.comboBoxFormulaHashOuCripto.SetSelection(
                        self._Criptografia_para_escolher.index(dados_separados[1]))
                    self.eventoComboBoxFormulaHashOuCripto(None)
                    self._txtChave.Clear()
                    self._txtChave.WriteText(dados_separados[2])
                    self._txtEntradaDados.Clear()
                    self._txtEntradaDados.WriteText(dados_separados[3])
            except KeyError:
                self.error_dialog(_('Não há nenhum arquivo com esse nome que possua configurações para esse programa.'))

    # def pesquisar(self, evt):
    #     dialog = wx.Fi


def rebuild(my_frame: MyWindow):
    tipo_alteracao = my_frame.comboBoxTipoAlteracao.GetSelection()
    tipo_hash_ou_cripto = my_frame.comboBoxFormulaHashOuCripto.GetSelection()
    tamanho_chave = my_frame.radio_btn_key_size.GetSelection()
    chave = my_frame._txtChave.GetValue()
    iv = my_frame._txtIV.GetValue()
    entrada_dados = my_frame._txtEntradaDados.GetValue()
    saida_dados = my_frame._txtSaidaDados.GetValue()

    my_frame.Hide()
    novo_frame = MyWindow()

    novo_frame.comboBoxTipoAlteracao.SetSelection(tipo_alteracao)
    novo_frame.comboBoxFormulaHashOuCripto.SetSelection(tipo_hash_ou_cripto)
    novo_frame.radio_btn_key_size.SetSelection(tamanho_chave)
    novo_frame._txtChave.SetValue(chave)
    novo_frame._txtIV.SetValue(iv)
    novo_frame._txtEntradaDados.SetValue(entrada_dados)
    novo_frame._txtSaidaDados.SetValue(saida_dados)

    my_frame.Destroy()
    novo_frame.Show()


if __name__ == '__main__':
    app = BaseApp()
    MyWindow()
    app.MainLoop()
