import sys
import os

import wx


# Install a custom displayhook to keep Python from setting the global
# _ (underscore) to the value of the last evaluated expression.  If
# we don't do this, our mapping of _ to gettext can get overwritten.
# This is useful/needed in interactive debugging with PyShell.

def _displayHook(obj):
    if obj is not None:
        print(repr(obj))


# add translation macro to builtin similar to what gettext does
import builtins

builtins.__dict__['_'] = wx.GetTranslation

import app_const as appC

from wx.lib.mixins.inspection import InspectionMixin


class BaseApp(wx.App, InspectionMixin):
    def OnInit(self):
        self.Init()  # InspectionMixin
        # work around for Python stealing "_"
        sys.displayhook = _displayHook

        self.appName = "Cyfer"

        # definindo linguas suportadas
        self.sup_languages = appC.supLang.keys()

        self.doConfig()

        self.locale = None
        wx.Locale.AddCatalogLookupPathPrefix('locale')
        self.updateLanguage(self.appConfig.Read(u"Language"))

        return True

    def doConfig(self):
        """Setup an application configuration file"""
        # configuration folder
        sp = wx.StandardPaths.Get()
        self.configLoc = sp.GetUserConfigDir()
        self.configLoc = os.path.join(self.configLoc, self.appName)

        if not os.path.exists(self.configLoc):
            os.mkdir(self.configLoc)

        # AppConfig stuff is here
        self.appConfig = wx.FileConfig(appName=self.appName,
                                       localFilename=os.path.join(
                                           self.configLoc, "AppConfig"))

        if not self.appConfig.HasEntry(u'Language'):
            # on first run we default to english
            self.appConfig.Write(key=u'Language', value=u'en_US')

        self.appConfig.Flush()

    def updateLanguage(self, lang):
        # if an unsupported language is requested default to Porteguese
        if lang in appC.supLang:
            selLang = appC.supLang[lang]

            # if is supporte update default config to new language
            self.appConfig = wx.FileConfig(appName=self.appName, localFilename=os.path.join(
                                               self.configLoc, "AppConfig"))

            self.appConfig.Write(key=u'Language', value=lang)

            self.appConfig.Flush()

        else:
            selLang = wx.LANGUAGE_PORTUGUESE_BRAZILIAN

        if self.locale:
            assert sys.getrefcount(self.locale) <= 2
            del self.locale

        # create a locale object for this language
        self.locale = wx.Locale(selLang)
        if self.locale.IsOk():
            self.locale.AddCatalog(appC.langDomain)
        else:
            self.locale = None

