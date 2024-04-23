# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'ids.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *

import images
import sources

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(1600, 900)
        icon = QIcon()
        icon.addFile(u":/newPrefix/aegis_logo_menu.png", QSize(), QIcon.Normal, QIcon.Off)
        MainWindow.setWindowIcon(icon)
        MainWindow.setStyleSheet(u"QMainWindow{\n"
"	\n"
"	\n"
"background-color: rgba(255, 255, 255,0);\n"
"	border-radius: 10px;\n"
"}\n"
"\n"
"\n"
"\n"
"")
        MainWindow.setIconSize(QSize(120, 120))
        MainWindow.setToolButtonStyle(Qt.ToolButtonIconOnly)
        MainWindow.setDockNestingEnabled(False)
        self.actionSalvar_automaticamente = QAction(MainWindow)
        self.actionSalvar_automaticamente.setObjectName(u"actionSalvar_automaticamente")
        self.actionSalvar_automaticamente.setCheckable(True)
        self.actionAtualizar_automaticamente = QAction(MainWindow)
        self.actionAtualizar_automaticamente.setObjectName(u"actionAtualizar_automaticamente")
        self.actionAtualizar_automaticamente.setCheckable(True)
        self.actionAbrir_DB = QAction(MainWindow)
        self.actionAbrir_DB.setObjectName(u"actionAbrir_DB")
        self.actionSalvar_Relatorio = QAction(MainWindow)
        self.actionSalvar_Relatorio.setObjectName(u"actionSalvar_Relatorio")
        self.actionAbrir_xlsx = QAction(MainWindow)
        self.actionAbrir_xlsx.setObjectName(u"actionAbrir_xlsx")
        self.actionImportar_xlsx = QAction(MainWindow)
        self.actionImportar_xlsx.setObjectName(u"actionImportar_xlsx")
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.centralwidget.setMinimumSize(QSize(0, 0))
        self.centralwidget.setStyleSheet(u"QWidget{\n"
"	\n"
"	\n"
"	background-color:rgb(196, 196, 196);\n"
"	border-radius: 10px;\n"
"	font: 25 14pt \"Bahnschrift Light Condensed\";\n"
"}\n"
"\n"
"")
        self.verticalLayout_8 = QVBoxLayout(self.centralwidget)
        self.verticalLayout_8.setSpacing(0)
        self.verticalLayout_8.setObjectName(u"verticalLayout_8")
        self.verticalLayout_8.setContentsMargins(0, 0, 0, 0)
        self.stackedWidget = QStackedWidget(self.centralwidget)
        self.stackedWidget.setObjectName(u"stackedWidget")
        self.stackedWidget.setStyleSheet(u"background-color: rgb(39, 37, 36);")
        self.login = QWidget()
        self.login.setObjectName(u"login")
        self.login.setStyleSheet(u"background-color: qradialgradient(spread:pad, cx:0.49, cy:0.502304, radius:0.687, fx:0.489, fy:0.51, stop:0 rgba(0, 28, 206, 243), stop:0.985843 rgba(0, 0, 0, 255));\n"
"background-position: center;\n"
"background-repeat:no-repeat;\n"
"border: 0px;\n"
"")
        self.verticalLayout = QVBoxLayout(self.login)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.content = QFrame(self.login)
        self.content.setObjectName(u"content")
        self.content.setStyleSheet(u"background-image: url();\n"
"background-color: qradialgradient(spread:pad, cx:0.49, cy:0.502304, radius:0.687, fx:0.489, fy:0.51, stop:0 rgba(0, 28, 206, 243), stop:0.985843 rgba(0, 0, 0, 255));\n"
"")
        self.content.setFrameShape(QFrame.NoFrame)
        self.content.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_3 = QHBoxLayout(self.content)
        self.horizontalLayout_3.setObjectName(u"horizontalLayout_3")
        self.login_area = QFrame(self.content)
        self.login_area.setObjectName(u"login_area")
        self.login_area.setMinimumSize(QSize(0, 0))
        self.login_area.setMaximumSize(QSize(600, 673))
        self.login_area.setCursor(QCursor(Qt.ArrowCursor))
        self.login_area.setLayoutDirection(Qt.LeftToRight)
        self.login_area.setAutoFillBackground(False)
        self.login_area.setStyleSheet(u"border-radius:13px;\n"
"border-image: url(:/login/login-src/5.jpg);;\n"
"background-position: center;\n"
"background-repeat:no-repeat;\n"
"\n"
"\n"
"")
        self.login_area.setFrameShape(QFrame.StyledPanel)
        self.login_area.setFrameShadow(QFrame.Raised)
        self.verticalLayout_4 = QVBoxLayout(self.login_area)
        self.verticalLayout_4.setObjectName(u"verticalLayout_4")
        self.verticalLayout_4.setContentsMargins(80, -1, 80, -1)
        self.logo = QFrame(self.login_area)
        self.logo.setObjectName(u"logo")
        self.logo.setMaximumSize(QSize(16777215, 16777215))
        self.logo.setLayoutDirection(Qt.LeftToRight)
        self.logo.setStyleSheet(u"background-image: url(:/newPrefix/aegis_logo.png);\n"
"background-position: center;\n"
"background-color: rgba(255, 255, 255, 0); \n"
"border-image:url();\n"
"background-repeat:no-repeat;\n"
"\n"
"")
        self.logo.setFrameShape(QFrame.StyledPanel)
        self.logo.setFrameShadow(QFrame.Raised)
        self.error_popup_area = QFrame(self.logo)
        self.error_popup_area.setObjectName(u"error_popup_area")
        self.error_popup_area.setGeometry(QRect(-10, 0, 451, 30))
        self.error_popup_area.setMinimumSize(QSize(440, 20))
        self.error_popup_area.setMaximumSize(QSize(16777215, 30))
        self.error_popup_area.setStyleSheet(u"background-image: url();\n"
"background-color: rgb(255, 0, 0);\n"
"border-style:none;\n"
"border-top-left-radius:0px;\n"
"border-top-right-radius:0px;")
        self.error_popup_area.setFrameShape(QFrame.NoFrame)
        self.error_popup_area.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_7 = QHBoxLayout(self.error_popup_area)
        self.horizontalLayout_7.setSpacing(0)
        self.horizontalLayout_7.setObjectName(u"horizontalLayout_7")
        self.horizontalLayout_7.setContentsMargins(0, 5, 0, 0)
        self.error_popup = QFrame(self.error_popup_area)
        self.error_popup.setObjectName(u"error_popup")
        self.error_popup.setMaximumSize(QSize(16777215, 16777215))
        self.error_popup.setStyleSheet(u"border-radius: 5px;\n"
"background-color: rgb(255, 0, 0);\n"
"")
        self.error_popup.setFrameShape(QFrame.StyledPanel)
        self.error_popup.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_8 = QHBoxLayout(self.error_popup)
        self.horizontalLayout_8.setSpacing(6)
        self.horizontalLayout_8.setObjectName(u"horizontalLayout_8")
        self.horizontalLayout_8.setContentsMargins(10, 3, 10, 3)
        self.error_text = QLabel(self.error_popup)
        self.error_text.setObjectName(u"error_text")
        self.error_text.setMinimumSize(QSize(300, 0))
        font = QFont()
        font.setFamily(u"Bahnschrift Light Condensed")
        font.setPointSize(14)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(3)
        self.error_text.setFont(font)
        self.error_text.setStyleSheet(u"border-style: none;\n"
"background-color: rgb(255, 0, 0);\n"
"border-radius: 5px;")
        self.error_text.setAlignment(Qt.AlignCenter)

        self.horizontalLayout_8.addWidget(self.error_text)

        self.cancel_error_popup = QPushButton(self.error_popup)
        self.cancel_error_popup.setObjectName(u"cancel_error_popup")
        self.cancel_error_popup.setMinimumSize(QSize(0, 20))
        self.cancel_error_popup.setMaximumSize(QSize(28, 35))
        self.cancel_error_popup.setStyleSheet(u"QPushButton {\n"
"	border-radius: 5px;\n"
"	border-image: url(:/newPrefix/cancel.png);\n"
"	background-position: center;\n"
"	border-style: solid;\n"
"	border-color: white;\n"
"	border-width: 2px;\n"
"	\n"
"	\n"
"\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"	\n"
"	background-color: rgb(50, 50, 50);\n"
"	color:rgb(202, 202, 202);\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"	\n"
"	background-color: rgb(34, 34, 34);\n"
"	color:rgb(202, 202, 202);\n"
"	border: 2px solid rgb(55,55,55)\n"
"}")

        self.horizontalLayout_8.addWidget(self.cancel_error_popup)


        self.horizontalLayout_7.addWidget(self.error_popup)


        self.verticalLayout_4.addWidget(self.logo)

        self.user_box = QFrame(self.login_area)
        self.user_box.setObjectName(u"user_box")
        self.user_box.setMaximumSize(QSize(16777215, 48))
        self.user_box.setStyleSheet(u"background-image: url();\n"
"background-color: rgba(255,255,255,30);\n"
"border-radius:10px;\n"
"border-image:url();\n"
"\n"
"\n"
"\n"
"")
        self.user_box.setFrameShape(QFrame.StyledPanel)
        self.user_box.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_4 = QHBoxLayout(self.user_box)
        self.horizontalLayout_4.setObjectName(u"horizontalLayout_4")
        self.horizontalLayout_4.setContentsMargins(9, -1, -1, -1)
        self.user_name_icon = QFrame(self.user_box)
        self.user_name_icon.setObjectName(u"user_name_icon")
        self.user_name_icon.setMinimumSize(QSize(35, 35))
        self.user_name_icon.setMaximumSize(QSize(60, 16777215))
        self.user_name_icon.setStyleSheet(u"border-image:url();\n"
"background-image: url(:/newPrefix/username.png);\n"
"background-color: rgba(255, 255, 255, 0); \n"
"")
        self.user_name_icon.setFrameShape(QFrame.StyledPanel)
        self.user_name_icon.setFrameShadow(QFrame.Raised)

        self.horizontalLayout_4.addWidget(self.user_name_icon)

        self.user_name_area = QFrame(self.user_box)
        self.user_name_area.setObjectName(u"user_name_area")
        self.user_name_area.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")
        self.user_name_area.setFrameShape(QFrame.StyledPanel)
        self.user_name_area.setFrameShadow(QFrame.Raised)
        self.verticalLayout_5 = QVBoxLayout(self.user_name_area)
        self.verticalLayout_5.setSpacing(0)
        self.verticalLayout_5.setObjectName(u"verticalLayout_5")
        self.verticalLayout_5.setContentsMargins(0, 0, 0, 0)
        self.user_name = QLineEdit(self.user_name_area)
        self.user_name.setObjectName(u"user_name")
        self.user_name.setMinimumSize(QSize(0, 0))
        self.user_name.setMaximumSize(QSize(16777215, 16777215))
        font1 = QFont()
        font1.setFamily(u"Bahnschrift Light Condensed")
        font1.setPointSize(14)
        font1.setBold(False)
        font1.setItalic(False)
        font1.setWeight(3)
        font1.setKerning(False)
        self.user_name.setFont(font1)
        self.user_name.setAutoFillBackground(False)
        self.user_name.setStyleSheet(u"color: rgb(255, 255, 255);\n"
"background-color: rgba(255, 255, 255, 0); \n"
"border-radius:0px;\n"
"")
        self.user_name.setMaxLength(35)

        self.verticalLayout_5.addWidget(self.user_name)


        self.horizontalLayout_4.addWidget(self.user_name_area)


        self.verticalLayout_4.addWidget(self.user_box)

        self.password_box = QFrame(self.login_area)
        self.password_box.setObjectName(u"password_box")
        self.password_box.setMaximumSize(QSize(16777215, 48))
        self.password_box.setStyleSheet(u"background-image: url();\n"
"background-color: rgba(255,255,255,30);\n"
"border-radius:10px;\n"
"border-image:url();")
        self.password_box.setFrameShape(QFrame.StyledPanel)
        self.password_box.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_5 = QHBoxLayout(self.password_box)
        self.horizontalLayout_5.setObjectName(u"horizontalLayout_5")
        self.horizontalLayout_5.setContentsMargins(9, -1, -1, -1)
        self.password_name_icon = QFrame(self.password_box)
        self.password_name_icon.setObjectName(u"password_name_icon")
        self.password_name_icon.setMinimumSize(QSize(35, 35))
        self.password_name_icon.setMaximumSize(QSize(60, 16777215))
        self.password_name_icon.setStyleSheet(u"background-image: url(:/newPrefix/password.png);\n"
"background-color: rgba(255, 255, 255, 0); \n"
"")
        self.password_name_icon.setFrameShape(QFrame.NoFrame)
        self.password_name_icon.setFrameShadow(QFrame.Raised)

        self.horizontalLayout_5.addWidget(self.password_name_icon)

        self.passsword_name_area = QFrame(self.password_box)
        self.passsword_name_area.setObjectName(u"passsword_name_area")
        self.passsword_name_area.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")
        self.passsword_name_area.setFrameShape(QFrame.StyledPanel)
        self.passsword_name_area.setFrameShadow(QFrame.Raised)
        self.verticalLayout_6 = QVBoxLayout(self.passsword_name_area)
        self.verticalLayout_6.setSpacing(0)
        self.verticalLayout_6.setObjectName(u"verticalLayout_6")
        self.verticalLayout_6.setContentsMargins(0, 0, 0, 0)
        self.password = QLineEdit(self.passsword_name_area)
        self.password.setObjectName(u"password")
        self.password.setMinimumSize(QSize(0, 0))
        self.password.setMaximumSize(QSize(16777215, 16777215))
        self.password.setFont(font)
        self.password.setStyleSheet(u"color: rgb(255, 255, 255);\n"
"background-color: rgba(255, 255, 255, 0); \n"
"border-radius:0px;\n"
"")
        self.password.setMaxLength(32767)
        self.password.setFrame(True)
        self.password.setEchoMode(QLineEdit.Password)

        self.verticalLayout_6.addWidget(self.password)


        self.horizontalLayout_5.addWidget(self.passsword_name_area)


        self.verticalLayout_4.addWidget(self.password_box)

        self.show_password_check_box = QCheckBox(self.login_area)
        self.show_password_check_box.setObjectName(u"show_password_check_box")
        self.show_password_check_box.setFont(font)
        self.show_password_check_box.setStyleSheet(u"color: rgb(255, 255, 255);\n"
"background-color: rgba(255, 255, 255, 0); \n"
"border-image:url();\n"
"")

        self.verticalLayout_4.addWidget(self.show_password_check_box)

        self.login_button = QPushButton(self.login_area)
        self.login_button.setObjectName(u"login_button")
        self.login_button.setMinimumSize(QSize(100, 60))
        self.login_button.setMaximumSize(QSize(16777215, 16777215))
        self.login_button.setFont(font)
        self.login_button.setStyleSheet(u"\n"
"\n"
"QPushButton{\n"
"\n"
"	border-radius:10px;\n"
"	color: rgb(255, 255, 255);\n"
"	border-image: NONE;\n"
"	background-color:rgba(255,255,255,10);\n"
"	border: 1px solid rgba(255,255,255,20);\n"
"	border-radius:7px;\n"
"}\n"
"\n"
"QPushButton:hover{\n"
"	\n"
"	\n"
"background-color:rgba(255,255,255,30);\n"
"}\n"
"\n"
"QPushButton:pressed{\n"
"	\n"
"	\n"
"background-color:rgba(255,255,255,70);\n"
"\n"
"}")

        self.verticalLayout_4.addWidget(self.login_button)


        self.horizontalLayout_3.addWidget(self.login_area)


        self.verticalLayout.addWidget(self.content)

        self.stackedWidget.addWidget(self.login)
        self.main = QWidget()
        self.main.setObjectName(u"main")
        self.main.setStyleSheet(u"")
        self.verticalLayout_7 = QVBoxLayout(self.main)
        self.verticalLayout_7.setSpacing(0)
        self.verticalLayout_7.setObjectName(u"verticalLayout_7")
        self.verticalLayout_7.setContentsMargins(0, 0, 0, 6)
        self.bar_window = QFrame(self.main)
        self.bar_window.setObjectName(u"bar_window")
        self.bar_window.setMinimumSize(QSize(0, 26))
        self.bar_window.setStyleSheet(u"background-color: rgb(39, 37, 36);")
        self.bar_window.setFrameShape(QFrame.NoFrame)
        self.bar_window.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_2 = QHBoxLayout(self.bar_window)
        self.horizontalLayout_2.setSpacing(0)
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.horizontalSpacer_5 = QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_2.addItem(self.horizontalSpacer_5)

        self.minimize = QPushButton(self.bar_window)
        self.minimize.setObjectName(u"minimize")
        self.minimize.setMinimumSize(QSize(40, 20))
        self.minimize.setStyleSheet(u"\n"
"\n"
"QPushButton{\n"
"	\n"
"	background-repeat:no-repeat;\n"
"	background-image: url(:/login/minimize.png);\n"
"	color: rgb(255, 255, 255);\n"
"	background-color: rgba(0, 0, 0, 0); \n"
"	 text-align: left;\n"
"	background-position: center;\n"
"\n"
"}\n"
"\n"
"QPushButton:hover{\n"
"	\n"
"	\n"
"background-color: rgba(0, 0, 0, 40); \n"
"\n"
"}\n"
"\n"
"QPushButton:pressed{\n"
"	\n"
"	background-image: url(:/login/minimize clik.png);\n"
"background-color: rgba(0, 0, 0, 75); \n"
"\n"
"}")

        self.horizontalLayout_2.addWidget(self.minimize)

        self.maxmize = QPushButton(self.bar_window)
        self.maxmize.setObjectName(u"maxmize")
        self.maxmize.setMinimumSize(QSize(40, 20))
        self.maxmize.setStyleSheet(u"\n"
"\n"
"QPushButton{\n"
"	\n"
"	background-repeat:no-repeat;\n"
"	background-image: url(:/login/max 1.png);\n"
"	color: rgb(255, 255, 255);\n"
"	background-color: rgba(0, 0, 0, 0); \n"
"	 text-align: left;\n"
"	background-position: center;\n"
"\n"
"}\n"
"\n"
"QPushButton:hover{\n"
"	\n"
"	\n"
"background-color: rgba(0, 0, 0, 40); \n"
"\n"
"}\n"
"\n"
"QPushButton:pressed{\n"
"	\n"
"	background-image: url(:/login/max_ click.png);\n"
"background-color: rgba(0, 0, 0, 75); \n"
"\n"
"}")

        self.horizontalLayout_2.addWidget(self.maxmize)

        self.exit = QPushButton(self.bar_window)
        self.exit.setObjectName(u"exit")
        self.exit.setMinimumSize(QSize(40, 20))
        self.exit.setStyleSheet(u"\n"
"\n"
"QPushButton{\n"
"	\n"
"	background-repeat:no-repeat;\n"
"	background-image: url(:/login/close.png);\n"
"	color: rgb(255, 255, 255);\n"
"	background-color: rgba(0, 0, 0, 0); \n"
"	 text-align: left;\n"
"	background-position: center;\n"
"\n"
"}\n"
"\n"
"QPushButton:hover{\n"
"	\n"
"	\n"
"background-color: rgba(0, 0, 0, 40); \n"
"\n"
"}\n"
"\n"
"QPushButton:pressed{\n"
"	\n"
"	background-image: url(:/login/close clik.png);\n"
"background-color: rgba(0, 0, 0, 75); \n"
"\n"
"}")

        self.horizontalLayout_2.addWidget(self.exit)


        self.verticalLayout_7.addWidget(self.bar_window)

        self.group = QFrame(self.main)
        self.group.setObjectName(u"group")
        self.group.setMinimumSize(QSize(0, 0))
        self.group.setStyleSheet(u"color: rgb(255, 255, 255);")
        self.group.setFrameShape(QFrame.StyledPanel)
        self.group.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_6 = QHBoxLayout(self.group)
        self.horizontalLayout_6.setSpacing(0)
        self.horizontalLayout_6.setObjectName(u"horizontalLayout_6")
        self.horizontalLayout_6.setContentsMargins(6, 0, 0, 0)
        self.menu = QFrame(self.group)
        self.menu.setObjectName(u"menu")
        self.menu.setMinimumSize(QSize(80, 0))
        self.menu.setMaximumSize(QSize(80, 16777215))
        self.menu.setStyleSheet(u"background-color: rgb(45, 45, 45);\n"
"border-top-right-radius:0px;\n"
"border-bottom-right-radius:0px;\n"
"\n"
"")
        self.menu.setFrameShape(QFrame.NoFrame)
        self.menu.setFrameShadow(QFrame.Raised)
        self.verticalLayout_26 = QVBoxLayout(self.menu)
        self.verticalLayout_26.setSpacing(0)
        self.verticalLayout_26.setObjectName(u"verticalLayout_26")
        self.verticalLayout_26.setContentsMargins(0, 0, 0, 0)
        self.categories = QFrame(self.menu)
        self.categories.setObjectName(u"categories")
        self.categories.setStyleSheet(u"background-color: rgba(0, 0, 0, 70);\n"
"border-top-left-radius:0px;\n"
"")
        self.categories.setFrameShape(QFrame.StyledPanel)
        self.categories.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_9 = QHBoxLayout(self.categories)
        self.horizontalLayout_9.setObjectName(u"horizontalLayout_9")
        self.scrollbar = QFrame(self.categories)
        self.scrollbar.setObjectName(u"scrollbar")
        self.scrollbar.setMinimumSize(QSize(5, 0))
        self.scrollbar.setMaximumSize(QSize(5, 16777215))
        self.scrollbar.setStyleSheet(u"background-color: rgba(0, 0, 0, 0);")
        self.scrollbar.setFrameShape(QFrame.StyledPanel)
        self.scrollbar.setFrameShadow(QFrame.Raised)
        self.page_indicator = QFrame(self.scrollbar)
        self.page_indicator.setObjectName(u"page_indicator")
        self.page_indicator.setGeometry(QRect(0, 60, 4, 60))
        self.page_indicator.setMinimumSize(QSize(0, 0))
        self.page_indicator.setMaximumSize(QSize(4, 60))
        self.page_indicator.setStyleSheet(u"background-color: rgb(0, 85, 255);")
        self.page_indicator.setFrameShape(QFrame.HLine)
        self.page_indicator.setFrameShadow(QFrame.Sunken)

        self.horizontalLayout_9.addWidget(self.scrollbar)

        self.topmenu = QFrame(self.categories)
        self.topmenu.setObjectName(u"topmenu")
        self.topmenu.setMinimumSize(QSize(0, 0))
        self.topmenu.setMaximumSize(QSize(16777215, 16777215))
        self.topmenu.setSizeIncrement(QSize(0, 20))
        self.topmenu.setStyleSheet(u"background-color: rgba(0, 0, 0, 0);")
        self.topmenu.setFrameShape(QFrame.StyledPanel)
        self.topmenu.setFrameShadow(QFrame.Raised)
        self.verticalLayout_27 = QVBoxLayout(self.topmenu)
        self.verticalLayout_27.setSpacing(0)
        self.verticalLayout_27.setObjectName(u"verticalLayout_27")
        self.verticalLayout_27.setContentsMargins(0, 0, 0, 0)
        self.menu_button = QPushButton(self.topmenu)
        self.menu_button.setObjectName(u"menu_button")
        self.menu_button.setMinimumSize(QSize(0, 0))
        self.menu_button.setFont(font)
        self.menu_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.menu_button.setStyleSheet(u"\n"
"\n"
"\n"
"\n"
"QPushButton{\n"
"\n"
"\n"
"	border-radius:0px;\n"
"\n"
"	padding:15px;\n"
"	color: rgb(255, 255, 255);\n"
"	background-color: rgba(0, 0, 0, 0); \n"
"	 text-align: left;\n"
"\n"
"}\n"
"\n"
"QPushButton:hover{\n"
"	\n"
"	\n"
"background-color: rgba(0, 0, 0, 40); \n"
"\n"
"}\n"
"\n"
"QPushButton:pressed{\n"
"	\n"
"font:  14pt \"Microsoft YaHei\";\n"
"background-color: rgba(0, 0, 0, 75); \n"
"\n"
"}")
        icon1 = QIcon()
        icon1.addFile(u":/menu/menu/togle2.png", QSize(), QIcon.Normal, QIcon.Off)
        self.menu_button.setIcon(icon1)
        self.menu_button.setIconSize(QSize(30, 30))

        self.verticalLayout_27.addWidget(self.menu_button)

        self.home_button = QPushButton(self.topmenu)
        self.home_button.setObjectName(u"home_button")
        self.home_button.setMinimumSize(QSize(0, 0))
        self.home_button.setMaximumSize(QSize(16777215, 16777215))
        self.home_button.setFont(font)
        self.home_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.home_button.setFocusPolicy(Qt.ClickFocus)
        self.home_button.setLayoutDirection(Qt.LeftToRight)
        self.home_button.setStyleSheet(u"\n"
"\n"
"\n"
"\n"
"QPushButton{\n"
"\n"
"\n"
"	border-radius:0px;\n"
"\n"
"	padding:15px;\n"
"	color: rgb(255, 255, 255);\n"
"	background-color: rgba(0, 0, 0, 0); \n"
"	 text-align: left;\n"
"\n"
"}\n"
"\n"
"QPushButton:hover{\n"
"	\n"
"	\n"
"background-color: rgba(0, 0, 0, 40); \n"
"\n"
"}\n"
"\n"
"QPushButton:pressed{\n"
"	\n"
"font:  14pt \"Microsoft YaHei\";\n"
"background-color: rgba(0, 0, 0, 75); \n"
"\n"
"}")
        icon2 = QIcon()
        icon2.addFile(u":/menu/menu/payout.png", QSize(), QIcon.Normal, QIcon.Off)
        self.home_button.setIcon(icon2)
        self.home_button.setIconSize(QSize(30, 30))

        self.verticalLayout_27.addWidget(self.home_button)

        self.settings_button = QPushButton(self.topmenu)
        self.settings_button.setObjectName(u"settings_button")
        self.settings_button.setMinimumSize(QSize(0, 0))
        self.settings_button.setFont(font)
        self.settings_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.settings_button.setStyleSheet(u"QPushButton{\n"
"	border-radius:0px;\n"
"	padding:15px;\n"
"	color: rgb(255, 255, 255);\n"
"	background-color: rgba(0, 0, 0, 0); \n"
"	 text-align: left;\n"
"}\n"
"QPushButton:hover{\n"
"  background-color: rgba(0, 0, 0, 40); \n"
"}\n"
"QPushButton:pressed{\n"
"  font:  14pt \"Microsoft YaHei\";\n"
"  background-color: rgba(0, 0, 0, 75); \n"
"}")
        icon3 = QIcon()
        icon3.addFile(u":/menu/menu/config.png", QSize(), QIcon.Normal, QIcon.Off)
        self.settings_button.setIcon(icon3)
        self.settings_button.setIconSize(QSize(30, 30))

        self.verticalLayout_27.addWidget(self.settings_button)

        self.verticalSpacer_2 = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)

        self.verticalLayout_27.addItem(self.verticalSpacer_2)

        self.logs_button = QPushButton(self.topmenu)
        self.logs_button.setObjectName(u"logs_button")
        self.logs_button.setMinimumSize(QSize(0, 0))
        self.logs_button.setMaximumSize(QSize(16777215, 16777215))
        self.logs_button.setFont(font)
        self.logs_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.logs_button.setStyleSheet(u"\n"
"\n"
"\n"
"\n"
"QPushButton{\n"
"\n"
"\n"
"	border-radius:0px;\n"
"\n"
"	padding:15px;\n"
"	color: rgb(255, 255, 255);\n"
"	background-color: rgba(0, 0, 0, 0); \n"
"	 text-align: left;\n"
"\n"
"}\n"
"\n"
"QPushButton:hover{\n"
"	\n"
"	\n"
"background-color: rgba(0, 0, 0, 40); \n"
"\n"
"}\n"
"\n"
"QPushButton:pressed{\n"
"	\n"
"font:  14pt \"Microsoft YaHei\";\n"
"background-color: rgba(0, 0, 0, 75); \n"
"\n"
"}")
        icon4 = QIcon()
        icon4.addFile(u":/menu/menu/db.png", QSize(), QIcon.Normal, QIcon.Off)
        self.logs_button.setIcon(icon4)
        self.logs_button.setIconSize(QSize(30, 30))

        self.verticalLayout_27.addWidget(self.logs_button)

        self.logout_button = QPushButton(self.topmenu)
        self.logout_button.setObjectName(u"logout_button")
        self.logout_button.setMinimumSize(QSize(0, 0))
        self.logout_button.setMaximumSize(QSize(16777215, 16777215))
        self.logout_button.setFont(font)
        self.logout_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.logout_button.setStyleSheet(u"QPushButton{\n"
"\n"
"\n"
"	border-radius:0px;\n"
"\n"
"	padding:15px;\n"
"	color: rgb(255, 255, 255);\n"
"	background-color: rgba(0, 0, 0, 0); \n"
"	 text-align: left;\n"
"\n"
"}\n"
"\n"
"QPushButton:hover{\n"
"	\n"
"	\n"
"background-color: rgba(0, 0, 0, 40); \n"
"\n"
"}\n"
"\n"
"QPushButton:pressed{\n"
"	\n"
"font:  14pt \"Microsoft YaHei\";\n"
"background-color: rgba(0, 0, 0, 75); \n"
"\n"
"}")
        icon5 = QIcon()
        icon5.addFile(u":/login/user.png", QSize(), QIcon.Normal, QIcon.Off)
        self.logout_button.setIcon(icon5)
        self.logout_button.setIconSize(QSize(30, 30))

        self.verticalLayout_27.addWidget(self.logout_button)

        self.exit_button = QPushButton(self.topmenu)
        self.exit_button.setObjectName(u"exit_button")
        self.exit_button.setMinimumSize(QSize(0, 0))
        self.exit_button.setMaximumSize(QSize(16777215, 16777215))
        self.exit_button.setFont(font)
        self.exit_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.exit_button.setStyleSheet(u"QPushButton{\n"
"\n"
"\n"
"	border-radius:0px;\n"
"\n"
"	padding:15px;\n"
"	color: rgb(255, 255, 255);\n"
"	background-color: rgba(0, 0, 0, 0); \n"
"	 text-align: left;\n"
"\n"
"}\n"
"\n"
"QPushButton:hover{\n"
"	\n"
"	\n"
"background-color: rgba(0, 0, 0, 40); \n"
"\n"
"}\n"
"\n"
"QPushButton:pressed{\n"
"	\n"
"font:  14pt \"Microsoft YaHei\";\n"
"background-color: rgba(0, 0, 0, 75); \n"
"\n"
"}")
        icon6 = QIcon()
        icon6.addFile(u":/menu/menu/powerof.png", QSize(), QIcon.Normal, QIcon.Off)
        self.exit_button.setIcon(icon6)
        self.exit_button.setIconSize(QSize(30, 30))

        self.verticalLayout_27.addWidget(self.exit_button)


        self.horizontalLayout_9.addWidget(self.topmenu)


        self.verticalLayout_26.addWidget(self.categories)


        self.horizontalLayout_6.addWidget(self.menu)

        self.stackedWidget_2 = QStackedWidget(self.group)
        self.stackedWidget_2.setObjectName(u"stackedWidget_2")
        self.stackedWidget_2.setStyleSheet(u"border-radius: 10px;")
        self.page_1 = QWidget()
        self.page_1.setObjectName(u"page_1")
        self.page_1.setStyleSheet(u"background-color: qlineargradient(spread:pad, x1:1, y1:1, x2:0, y2:0, stop:0 rgba(81, 0, 135, 255), stop:0.427447 rgba(41, 61, 132, 235), stop:1 rgba(155, 79, 165, 255));\n"
"")
        self.verticalLayout_2 = QVBoxLayout(self.page_1)
        self.verticalLayout_2.setSpacing(0)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.frame_40 = QFrame(self.page_1)
        self.frame_40.setObjectName(u"frame_40")
        self.frame_40.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); \n"
"border-radius:7px;")
        self.frame_40.setFrameShape(QFrame.StyledPanel)
        self.frame_40.setFrameShadow(QFrame.Raised)
        self.verticalLayout_33 = QVBoxLayout(self.frame_40)
        self.verticalLayout_33.setSpacing(0)
        self.verticalLayout_33.setObjectName(u"verticalLayout_33")
        self.verticalLayout_33.setContentsMargins(0, 0, 0, 0)
        self.frame_42 = QFrame(self.frame_40)
        self.frame_42.setObjectName(u"frame_42")
        self.frame_42.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")
        self.frame_42.setFrameShape(QFrame.StyledPanel)
        self.frame_42.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_50 = QHBoxLayout(self.frame_42)
        self.horizontalLayout_50.setObjectName(u"horizontalLayout_50")
        self.horizontalLayout_50.setContentsMargins(0, 0, 0, 0)
        self.scrollArea_6 = QScrollArea(self.frame_42)
        self.scrollArea_6.setObjectName(u"scrollArea_6")
        self.scrollArea_6.setMinimumSize(QSize(0, 0))
        self.scrollArea_6.setStyleSheet(u"/* VERTICAL SCROLLBAR */\n"
" QScrollBar:vertical {\n"
"	border: none;\n"
"    background: rgb(45, 45, 68);\n"
"    width: 5px;\n"
"    margin: 15px 0 15px 0;\n"
"	border-radius: 0px;\n"
" }\n"
"\n"
"/*  HANDLE BAR VERTICAL */\n"
"QScrollBar::handle:vertical {	\n"
"	background-color: rgb(80, 80, 122);\n"
"	min-height: 30px;\n"
"	border-radius: 7px;\n"
"}\n"
"QScrollBar::handle:vertical:hover{	\n"
"	background-color: rgb(255, 0, 127);\n"
"}\n"
"QScrollBar::handle:vertical:pressed {	\n"
"	background-color: rgb(185, 0, 92);\n"
"}\n"
"\n"
"/* BTN TOP - SCROLLBAR */\n"
"QScrollBar::sub-line:vertical {\n"
"	border: none;\n"
"	background-color: rgb(59, 59, 90);\n"
"	height: 15px;\n"
"	border-top-left-radius: 7px;\n"
"	border-top-right-radius: 7px;\n"
"	subcontrol-position: top;\n"
"	subcontrol-origin: margin;\n"
"}\n"
"QScrollBar::sub-line:vertical:hover {	\n"
"	background-color: rgb(255, 0, 127);\n"
"}\n"
"QScrollBar::sub-line:vertical:pressed {	\n"
"	background-color: rgb(185, 0, 92);\n"
"}\n"
"\n"
"/* BTN BOTTOM -"
                        " SCROLLBAR */\n"
"QScrollBar::add-line:vertical {\n"
"	border: none;\n"
"	background-color: rgb(59, 59, 90);\n"
"	height: 15px;\n"
"	border-bottom-left-radius: 7px;\n"
"	border-bottom-right-radius: 7px;\n"
"	subcontrol-position: bottom;\n"
"	subcontrol-origin: margin;\n"
"}\n"
"QScrollBar::add-line:vertical:hover {	\n"
"	background-color: rgb(255, 0, 127);\n"
"}\n"
"QScrollBar::add-line:vertical:pressed {	\n"
"	background-color: rgb(185, 0, 92);\n"
"}\n"
"\n"
"/* RESET ARROW */\n"
"QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {\n"
"	background: none;\n"
"}\n"
"QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {\n"
"	background: none;\n"
"}\n"
"\n"
"\n"
"\n"
"/* HORIZONTAL SCROLLBAR - HOMEWORK */\n"
"QScrollBar:horizontal {\n"
"   \n"
"}\n"
"QScrollBar::handle:horizontal {\n"
"    \n"
"}\n"
"QScrollBar::add-line:horizontal {\n"
"    \n"
"}\n"
"QScrollBar::sub-line:horizontal {\n"
"    \n"
"}\n"
"QScrollBar::up-arrow:horizontal, QScrollBar::down-arrow:horizontal\n"
"{\n"
"\n"
"}\n"
""
                        "QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal\n"
"{\n"
"\n"
"}\n"
"\n"
"\n"
"")
        self.scrollArea_6.setFrameShadow(QFrame.Raised)
        self.scrollArea_6.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.scrollArea_6.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.scrollArea_6.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContentsOnFirstShow)
        self.scrollArea_6.setWidgetResizable(True)
        self.scrollAreaWidgetContents_6 = QWidget()
        self.scrollAreaWidgetContents_6.setObjectName(u"scrollAreaWidgetContents_6")
        self.scrollAreaWidgetContents_6.setGeometry(QRect(0, 0, 1514, 866))
        self.scrollAreaWidgetContents_6.setStyleSheet(u"background-color: rgba(255, 255, 255, 0);")
        self.horizontalLayout_51 = QHBoxLayout(self.scrollAreaWidgetContents_6)
        self.horizontalLayout_51.setSpacing(0)
        self.horizontalLayout_51.setObjectName(u"horizontalLayout_51")
        self.horizontalLayout_51.setContentsMargins(0, 0, 0, 0)
        self.dashboard = QFrame(self.scrollAreaWidgetContents_6)
        self.dashboard.setObjectName(u"dashboard")
        self.dashboard.setMinimumSize(QSize(0, 0))
        self.dashboard.setMaximumSize(QSize(440, 16777215))
        self.dashboard.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")
        self.dashboard.setFrameShape(QFrame.StyledPanel)
        self.dashboard.setFrameShadow(QFrame.Raised)
        self.verticalLayout_43 = QVBoxLayout(self.dashboard)
        self.verticalLayout_43.setSpacing(30)
        self.verticalLayout_43.setObjectName(u"verticalLayout_43")
        self.verticalLayout_43.setContentsMargins(0, 0, 0, 0)

        self.horizontalLayout_51.addWidget(self.dashboard)

        self.dashboard_card = QStackedWidget(self.scrollAreaWidgetContents_6)
        self.dashboard_card.setObjectName(u"dashboard_card")
        self.dashboard_card.setFont(font)
        self.dashboard_card.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")
        self.dashboard_card.setFrameShape(QFrame.StyledPanel)
        self.dashboard_card.setFrameShadow(QFrame.Raised)
        self.dashboard_cards_2 = QWidget()
        self.dashboard_cards_2.setObjectName(u"dashboard_cards_2")
        self.dashboard_cards_2.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")
        self.horizontalLayout_121 = QHBoxLayout(self.dashboard_cards_2)
        self.horizontalLayout_121.setSpacing(0)
        self.horizontalLayout_121.setObjectName(u"horizontalLayout_121")
        self.horizontalLayout_121.setContentsMargins(0, 0, 0, 0)
        self.horizontalSpacer_26 = QSpacerItem(0, 20, QSizePolicy.Preferred, QSizePolicy.Minimum)

        self.horizontalLayout_121.addItem(self.horizontalSpacer_26)

        self.scrollArea_9 = QScrollArea(self.dashboard_cards_2)
        self.scrollArea_9.setObjectName(u"scrollArea_9")
        self.scrollArea_9.setMinimumSize(QSize(0, 0))
        self.scrollArea_9.setMaximumSize(QSize(1486, 950))
        self.scrollArea_9.setLayoutDirection(Qt.LeftToRight)
        self.scrollArea_9.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")
        self.scrollArea_9.setFrameShape(QFrame.StyledPanel)
        self.scrollArea_9.setFrameShadow(QFrame.Plain)
        self.scrollArea_9.setLineWidth(1)
        self.scrollArea_9.setMidLineWidth(0)
        self.scrollArea_9.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.scrollArea_9.setWidgetResizable(True)
        self.scrollAreaWidgetContents_9 = QWidget()
        self.scrollAreaWidgetContents_9.setObjectName(u"scrollAreaWidgetContents_9")
        self.scrollAreaWidgetContents_9.setGeometry(QRect(0, 0, 1486, 866))
        self.scrollAreaWidgetContents_9.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")
        self.verticalLayout_10 = QVBoxLayout(self.scrollAreaWidgetContents_9)
        self.verticalLayout_10.setObjectName(u"verticalLayout_10")
        self.user_and_usage_area = QFrame(self.scrollAreaWidgetContents_9)
        self.user_and_usage_area.setObjectName(u"user_and_usage_area")
        self.user_and_usage_area.setMinimumSize(QSize(200, 200))
        self.user_and_usage_area.setMaximumSize(QSize(16777215, 16777215))
        self.user_and_usage_area.setStyleSheet(u"")
        self.user_and_usage_area.setFrameShape(QFrame.StyledPanel)
        self.user_and_usage_area.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_65 = QHBoxLayout(self.user_and_usage_area)
        self.horizontalLayout_65.setSpacing(10)
        self.horizontalLayout_65.setObjectName(u"horizontalLayout_65")
        self.horizontalLayout_65.setContentsMargins(0, 0, 0, 0)
        self.user_info = QFrame(self.user_and_usage_area)
        self.user_info.setObjectName(u"user_info")
        self.user_info.setMinimumSize(QSize(200, 200))
        self.user_info.setMaximumSize(QSize(200, 200))
        self.user_info.setStyleSheet(u"\n"
"border-image:none;\n"
"background-color: rgba(255, 255, 255, 30); \n"
"border:1px solid rgba(255,255,255,40);")
        self.user_info.setFrameShape(QFrame.NoFrame)
        self.user_info.setFrameShadow(QFrame.Raised)
        self.verticalLayout_37 = QVBoxLayout(self.user_info)
        self.verticalLayout_37.setObjectName(u"verticalLayout_37")
        self.frame_44 = QFrame(self.user_info)
        self.frame_44.setObjectName(u"frame_44")
        self.frame_44.setMinimumSize(QSize(0, 60))
        self.frame_44.setStyleSheet(u"background-color:none;\n"
"border:none;")
        self.frame_44.setFrameShape(QFrame.StyledPanel)
        self.frame_44.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_52 = QHBoxLayout(self.frame_44)
        self.horizontalLayout_52.setSpacing(0)
        self.horizontalLayout_52.setObjectName(u"horizontalLayout_52")
        self.horizontalLayout_52.setContentsMargins(0, 0, 0, 0)
        self.horizontalSpacer_22 = QSpacerItem(58, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_52.addItem(self.horizontalSpacer_22)

        self.frame_45 = QFrame(self.frame_44)
        self.frame_45.setObjectName(u"frame_45")
        self.frame_45.setMinimumSize(QSize(60, 0))
        self.frame_45.setStyleSheet(u"background-repeat:no-repeat;\n"
"background-position:center;\n"
"background-image: url(:/newPrefix/user_info.png);\n"
"")
        self.frame_45.setFrameShape(QFrame.StyledPanel)
        self.frame_45.setFrameShadow(QFrame.Raised)

        self.horizontalLayout_52.addWidget(self.frame_45)

        self.horizontalSpacer_23 = QSpacerItem(58, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_52.addItem(self.horizontalSpacer_23)


        self.verticalLayout_37.addWidget(self.frame_44)

        self.user_name_info = QLabel(self.user_info)
        self.user_name_info.setObjectName(u"user_name_info")
        self.user_name_info.setStyleSheet(u"background-color:rgba(255,255,255,0);\n"
"border:none;")
        self.user_name_info.setAlignment(Qt.AlignCenter)

        self.verticalLayout_37.addWidget(self.user_name_info)

        self.label_42 = QLabel(self.user_info)
        self.label_42.setObjectName(u"label_42")
        self.label_42.setStyleSheet(u"background-color:rgba(255,255,255,0);\n"
"border:none;")
        self.label_42.setAlignment(Qt.AlignCenter)

        self.verticalLayout_37.addWidget(self.label_42)


        self.horizontalLayout_65.addWidget(self.user_info)

        self.frame = QFrame(self.user_and_usage_area)
        self.frame.setObjectName(u"frame")
        self.frame.setFrameShape(QFrame.StyledPanel)
        self.frame.setFrameShadow(QFrame.Raised)
        self.cpu_usage_graph = QWidget(self.frame)
        self.cpu_usage_graph.setObjectName(u"cpu_usage_graph")
        self.cpu_usage_graph.setGeometry(QRect(10, 0, 400, 200))
        self.cpu_usage_graph.setMinimumSize(QSize(400, 200))
        self.cpu_usage_graph.setMaximumSize(QSize(400, 200))
        self.cpu_usage_graph.setStyleSheet(u"background-color: rgba(255, 255, 255, 30); \n"
"border:1px solid rgba(255,255,255,40);")
        self.horizontalLayout_13 = QHBoxLayout(self.cpu_usage_graph)
        self.horizontalLayout_13.setSpacing(0)
        self.horizontalLayout_13.setObjectName(u"horizontalLayout_13")
        self.horizontalLayout_13.setContentsMargins(0, 0, 0, 0)
        self.cpu_graph_area = QWidget(self.cpu_usage_graph)
        self.cpu_graph_area.setObjectName(u"cpu_graph_area")
        self.cpu_graph_area.setMinimumSize(QSize(261, 200))
        self.cpu_graph_area.setMaximumSize(QSize(261, 200))

        self.horizontalLayout_13.addWidget(self.cpu_graph_area)

        self.cpu_labels_area = QWidget(self.cpu_usage_graph)
        self.cpu_labels_area.setObjectName(u"cpu_labels_area")
        self.cpu_labels_area.setMinimumSize(QSize(141, 200))
        self.cpu_labels_area.setMaximumSize(QSize(141, 200))
        self.cpu_label = QLabel(self.cpu_labels_area)
        self.cpu_label.setObjectName(u"cpu_label")
        self.cpu_label.setGeometry(QRect(30, 10, 81, 41))
        self.cpu_label.setAlignment(Qt.AlignCenter)
        self.cpu_usage_label = QLabel(self.cpu_labels_area)
        self.cpu_usage_label.setObjectName(u"cpu_usage_label")
        self.cpu_usage_label.setGeometry(QRect(20, 80, 101, 31))
        self.cpu_usage_label.setAlignment(Qt.AlignCenter)
        self.cpu_frequency_label = QLabel(self.cpu_labels_area)
        self.cpu_frequency_label.setObjectName(u"cpu_frequency_label")
        self.cpu_frequency_label.setGeometry(QRect(20, 120, 101, 31))
        self.cpu_frequency_label.setAlignment(Qt.AlignCenter)

        self.horizontalLayout_13.addWidget(self.cpu_labels_area)

        self.memory_usage_graph = QWidget(self.frame)
        self.memory_usage_graph.setObjectName(u"memory_usage_graph")
        self.memory_usage_graph.setGeometry(QRect(430, 0, 400, 200))
        self.memory_usage_graph.setMinimumSize(QSize(400, 200))
        self.memory_usage_graph.setMaximumSize(QSize(400, 200))
        self.memory_usage_graph.setStyleSheet(u"background-color: rgba(255, 255, 255, 30); \n"
"border:1px solid rgba(255,255,255,40);")
        self.horizontalLayout_14 = QHBoxLayout(self.memory_usage_graph)
        self.horizontalLayout_14.setSpacing(0)
        self.horizontalLayout_14.setObjectName(u"horizontalLayout_14")
        self.horizontalLayout_14.setContentsMargins(0, 0, 0, 0)
        self.memory_graph_area = QWidget(self.memory_usage_graph)
        self.memory_graph_area.setObjectName(u"memory_graph_area")
        self.memory_graph_area.setMinimumSize(QSize(261, 201))
        self.memory_graph_area.setMaximumSize(QSize(261, 201))

        self.horizontalLayout_14.addWidget(self.memory_graph_area)

        self.memory_labels_area = QWidget(self.memory_usage_graph)
        self.memory_labels_area.setObjectName(u"memory_labels_area")
        self.memory_labels_area.setMinimumSize(QSize(141, 200))
        self.memory_labels_area.setMaximumSize(QSize(141, 200))
        self.memory_label = QLabel(self.memory_labels_area)
        self.memory_label.setObjectName(u"memory_label")
        self.memory_label.setGeometry(QRect(30, 10, 81, 41))
        self.memory_label.setAlignment(Qt.AlignCenter)
        self.memory_usage_label = QLabel(self.memory_labels_area)
        self.memory_usage_label.setObjectName(u"memory_usage_label")
        self.memory_usage_label.setGeometry(QRect(0, 80, 141, 50))
        self.memory_usage_label.setAlignment(Qt.AlignCenter)

        self.horizontalLayout_14.addWidget(self.memory_labels_area)

        self.network_throughput_graph = QWidget(self.frame)
        self.network_throughput_graph.setObjectName(u"network_throughput_graph")
        self.network_throughput_graph.setGeometry(QRect(850, 0, 400, 200))
        self.network_throughput_graph.setMinimumSize(QSize(400, 200))
        self.network_throughput_graph.setMaximumSize(QSize(400, 200))
        self.network_throughput_graph.setStyleSheet(u"background-color: rgba(255, 255, 255, 30); \n"
"border:1px solid rgba(255,255,255,40);")
        self.horizontalLayout_15 = QHBoxLayout(self.network_throughput_graph)
        self.horizontalLayout_15.setSpacing(0)
        self.horizontalLayout_15.setObjectName(u"horizontalLayout_15")
        self.horizontalLayout_15.setContentsMargins(0, 0, 0, 0)
        self.network_graph_area = QWidget(self.network_throughput_graph)
        self.network_graph_area.setObjectName(u"network_graph_area")
        self.network_graph_area.setMinimumSize(QSize(261, 201))
        self.network_graph_area.setMaximumSize(QSize(261, 201))

        self.horizontalLayout_15.addWidget(self.network_graph_area)

        self.network_labels_area = QWidget(self.network_throughput_graph)
        self.network_labels_area.setObjectName(u"network_labels_area")
        self.network_labels_area.setMinimumSize(QSize(141, 200))
        self.network_labels_area.setMaximumSize(QSize(141, 200))
        self.netwrok_label = QLabel(self.network_labels_area)
        self.netwrok_label.setObjectName(u"netwrok_label")
        self.netwrok_label.setGeometry(QRect(30, 10, 81, 41))
        self.network_throughput_label = QLabel(self.network_labels_area)
        self.network_throughput_label.setObjectName(u"network_throughput_label")
        self.network_throughput_label.setGeometry(QRect(10, 80, 121, 50))
        self.network_throughput_label.setAlignment(Qt.AlignCenter)
        self.network_throughput_label_2 = QLabel(self.network_labels_area)
        self.network_throughput_label_2.setObjectName(u"network_throughput_label_2")
        self.network_throughput_label_2.setGeometry(QRect(10, 140, 121, 50))
        self.network_throughput_label_2.setAlignment(Qt.AlignCenter)

        self.horizontalLayout_15.addWidget(self.network_labels_area)


        self.horizontalLayout_65.addWidget(self.frame)


        self.verticalLayout_10.addWidget(self.user_and_usage_area)

        self.dashboard_control_area = QStackedWidget(self.scrollAreaWidgetContents_9)
        self.dashboard_control_area.setObjectName(u"dashboard_control_area")
        self.dashboard_control_area.setMaximumSize(QSize(16777215, 60))
        self.dashboard_control_area.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); \n"
"border-radius:7px;\n"
"")
        self.dashboard_control_area.setFrameShape(QFrame.StyledPanel)
        self.dashboard_control_area.setFrameShadow(QFrame.Raised)
        self.page_11 = QWidget()
        self.page_11.setObjectName(u"page_11")
        self.horizontalLayout_11 = QHBoxLayout(self.page_11)
        self.horizontalLayout_11.setObjectName(u"horizontalLayout_11")
        self.power_button = QPushButton(self.page_11)
        self.power_button.setObjectName(u"power_button")
        self.power_button.setMinimumSize(QSize(50, 50))
        self.power_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.power_button.setAutoFillBackground(False)
        self.power_button.setStyleSheet(u"QPushButton:pressed {\n"
"    background-color: rgba(81, 0, 135, 0.3);\n"
"}\n"
"")
        icon7 = QIcon()
        icon7.addFile(u":/newPrefix/power_button.png", QSize(), QIcon.Normal, QIcon.Off)
        self.power_button.setIcon(icon7)
        self.power_button.setIconSize(QSize(68, 50))
        self.power_button.setCheckable(True)

        self.horizontalLayout_11.addWidget(self.power_button)

        self.horizontalSpacer_27 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_11.addItem(self.horizontalSpacer_27)

        self.label_67 = QLabel(self.page_11)
        self.label_67.setObjectName(u"label_67")
        self.label_67.setMinimumSize(QSize(80, 0))
        self.label_67.setMaximumSize(QSize(80, 16777215))
        self.label_67.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")

        self.horizontalLayout_11.addWidget(self.label_67)

        self.horizontalSpacer_28 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.horizontalLayout_11.addItem(self.horizontalSpacer_28)

        self.dashboard_control_area.addWidget(self.page_11)

        self.verticalLayout_10.addWidget(self.dashboard_control_area)

        self.live_area = QFrame(self.scrollAreaWidgetContents_9)
        self.live_area.setObjectName(u"live_area")
        self.live_area.setMinimumSize(QSize(0, 0))
        self.live_area.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")
        self.live_area.setFrameShape(QFrame.StyledPanel)
        self.live_area.setFrameShadow(QFrame.Raised)
        self.verticalLayout_56 = QVBoxLayout(self.live_area)
        self.verticalLayout_56.setSpacing(0)
        self.verticalLayout_56.setObjectName(u"verticalLayout_56")
        self.verticalLayout_56.setContentsMargins(0, 0, 0, 0)
        self.live_area_chart = QTabWidget(self.live_area)
        self.live_area_chart.setObjectName(u"live_area_chart")
        self.live_area_chart.setMinimumSize(QSize(0, 0))
        self.live_area_chart.setMaximumSize(QSize(16777215, 16777215))
        self.live_area_chart.setFont(font)
        self.live_area_chart.setLayoutDirection(Qt.LeftToRight)
        self.live_area_chart.setStyleSheet(u"\n"
"\n"
"QTabWidget::tab-bar {\n"
"  background: rgba(255,255,255,0);\n"
"\n"
"}\n"
"\n"
"\n"
"QTabBar::tab {\n"
"  background: rgb(46, 46, 46);\n"
"  color: rgb(255, 255, 255);\n"
"  padding: 10px;\n"
"\n"
" }\n"
"\n"
" QTabBar::tab:selected {\n"
"  background:rgb(53, 53, 53);\n"
"  color: rgb(255, 255, 255);\n"
" }\n"
"\n"
"QTabWidget::pane { border-top-left-radius:0px; border-top-right-radius:0px;}\n"
"\n"
"")
        self.live_area_chart.setTabPosition(QTabWidget.North)
        self.live_area_chart.setTabShape(QTabWidget.Rounded)
        self.live_area_chart.setElideMode(Qt.ElideMiddle)
        self.live_area_chart.setDocumentMode(False)
        self.live_area_chart.setTabsClosable(False)
        self.live_area_chart.setMovable(True)
        self.live_area_chart.setTabBarAutoHide(True)
        self.page_Tabe_main1 = QWidget()
        self.page_Tabe_main1.setObjectName(u"page_Tabe_main1")
        self.page_Tabe_main1.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")
        self.verticalLayout_140 = QVBoxLayout(self.page_Tabe_main1)
        self.verticalLayout_140.setSpacing(0)
        self.verticalLayout_140.setObjectName(u"verticalLayout_140")
        self.verticalLayout_140.setContentsMargins(0, 0, 10, 0)
        self.live_network_feed_card = QFrame(self.page_Tabe_main1)
        self.live_network_feed_card.setObjectName(u"live_network_feed_card")
        self.live_network_feed_card.setStyleSheet(u"")
        self.live_network_feed_card.setFrameShape(QFrame.StyledPanel)
        self.live_network_feed_card.setFrameShadow(QFrame.Raised)
        self.verticalLayout_141 = QVBoxLayout(self.live_network_feed_card)
        self.verticalLayout_141.setSpacing(0)
        self.verticalLayout_141.setObjectName(u"verticalLayout_141")
        self.verticalLayout_141.setContentsMargins(0, 0, 0, 0)
        self.frame_55 = QFrame(self.live_network_feed_card)
        self.frame_55.setObjectName(u"frame_55")
        self.frame_55.setStyleSheet(u"")
        self.frame_55.setFrameShape(QFrame.StyledPanel)
        self.frame_55.setFrameShadow(QFrame.Raised)
        self.verticalLayout_59 = QVBoxLayout(self.frame_55)
        self.verticalLayout_59.setSpacing(0)
        self.verticalLayout_59.setObjectName(u"verticalLayout_59")
        self.verticalLayout_59.setContentsMargins(0, 0, 0, 0)
        self.frame_56 = QFrame(self.frame_55)
        self.frame_56.setObjectName(u"frame_56")
        self.frame_56.setStyleSheet(u"border:none;\n"
"")
        self.frame_56.setFrameShape(QFrame.StyledPanel)
        self.frame_56.setFrameShadow(QFrame.Raised)
        self.verticalLayout_60 = QVBoxLayout(self.frame_56)
        self.verticalLayout_60.setSpacing(0)
        self.verticalLayout_60.setObjectName(u"verticalLayout_60")
        self.verticalLayout_60.setContentsMargins(0, 0, 0, 0)
        self.scrollArea_7 = QScrollArea(self.frame_56)
        self.scrollArea_7.setObjectName(u"scrollArea_7")
        self.scrollArea_7.setMinimumSize(QSize(0, 0))
        self.scrollArea_7.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")
        self.scrollArea_7.setWidgetResizable(True)
        self.scrollAreaWidgetContents_7 = QWidget()
        self.scrollAreaWidgetContents_7.setObjectName(u"scrollAreaWidgetContents_7")
        self.scrollAreaWidgetContents_7.setGeometry(QRect(0, 0, 1454, 522))
        self.scrollAreaWidgetContents_7.setStyleSheet(u"")
        self.verticalLayout_61 = QVBoxLayout(self.scrollAreaWidgetContents_7)
        self.verticalLayout_61.setSpacing(0)
        self.verticalLayout_61.setObjectName(u"verticalLayout_61")
        self.verticalLayout_61.setContentsMargins(0, 0, 0, 0)
        self.frame_93 = QFrame(self.scrollAreaWidgetContents_7)
        self.frame_93.setObjectName(u"frame_93")
        self.frame_93.setMinimumSize(QSize(0, 0))
        self.frame_93.setStyleSheet(u"background-color: rgba(255, 255, 255, 30); ")
        self.frame_93.setFrameShape(QFrame.StyledPanel)
        self.frame_93.setFrameShadow(QFrame.Raised)
        self.verticalLayout_92 = QVBoxLayout(self.frame_93)
        self.verticalLayout_92.setSpacing(0)
        self.verticalLayout_92.setObjectName(u"verticalLayout_92")
        self.verticalLayout_92.setContentsMargins(0, 0, 0, 0)
        self.frame_57 = QFrame(self.frame_93)
        self.frame_57.setObjectName(u"frame_57")
        self.frame_57.setMaximumSize(QSize(16777215, 16777215))
        self.frame_57.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")
        self.frame_57.setFrameShape(QFrame.StyledPanel)
        self.frame_57.setFrameShadow(QFrame.Raised)
        self.verticalLayout_62 = QVBoxLayout(self.frame_57)
        self.verticalLayout_62.setSpacing(0)
        self.verticalLayout_62.setObjectName(u"verticalLayout_62")
        self.verticalLayout_62.setContentsMargins(0, 0, 0, 0)
        self.live_feed_and_alerts = QFrame(self.frame_57)
        self.live_feed_and_alerts.setObjectName(u"live_feed_and_alerts")
        self.live_feed_and_alerts.setMinimumSize(QSize(0, 90))
        self.live_feed_and_alerts.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); \n"
"")
        self.live_feed_and_alerts.setFrameShape(QFrame.StyledPanel)
        self.live_feed_and_alerts.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_53 = QHBoxLayout(self.live_feed_and_alerts)
        self.horizontalLayout_53.setSpacing(0)
        self.horizontalLayout_53.setObjectName(u"horizontalLayout_53")
        self.horizontalLayout_53.setContentsMargins(0, 0, 0, 0)
        self.live_feed_table_area = QStackedWidget(self.live_feed_and_alerts)
        self.live_feed_table_area.setObjectName(u"live_feed_table_area")
        self.live_feed_table_area.setMinimumSize(QSize(0, 0))
        self.live_feed_table_area.setMaximumSize(QSize(16777215, 16777215))
        self.live_feed_table_area.setFrameShape(QFrame.StyledPanel)
        self.live_feed_table_area.setFrameShadow(QFrame.Raised)
        self.live_feed_table_card = QWidget()
        self.live_feed_table_card.setObjectName(u"live_feed_table_card")
        self.horizontalLayout_54 = QHBoxLayout(self.live_feed_table_card)
        self.horizontalLayout_54.setSpacing(0)
        self.horizontalLayout_54.setObjectName(u"horizontalLayout_54")
        self.horizontalLayout_54.setContentsMargins(0, 0, 0, 0)
        self.tableWidget = QTableWidget(self.live_feed_table_card)
        if (self.tableWidget.columnCount() < 8):
            self.tableWidget.setColumnCount(8)
        __qtablewidgetitem = QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, __qtablewidgetitem)
        __qtablewidgetitem1 = QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        __qtablewidgetitem2 = QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(2, __qtablewidgetitem2)
        __qtablewidgetitem3 = QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(3, __qtablewidgetitem3)
        __qtablewidgetitem4 = QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(4, __qtablewidgetitem4)
        __qtablewidgetitem5 = QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(5, __qtablewidgetitem5)
        __qtablewidgetitem6 = QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(6, __qtablewidgetitem6)
        __qtablewidgetitem7 = QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(7, __qtablewidgetitem7)
        self.tableWidget.setObjectName(u"tableWidget")
        self.tableWidget.setMaximumSize(QSize(16777215, 16777215))
        self.tableWidget.setFont(font)
        self.tableWidget.setStyleSheet(u"QWidget {\n"
"	\n"
"    color: #fffff8;\n"
"	border-radius:0px;\n"
"\n"
"\n"
"\n"
"}\n"
"\n"
"QHeaderView::section {\n"
"    background-color: rgb(53, 53, 53);\n"
"	border:none;\n"
"	width:45px;\n"
"	height: 50px;\n"
"	margin-left:1px;\n"
"\n"
"	border-radius:0px;\n"
"\n"
"\n"
"}\n"
"\n"
"QTableWidget {\n"
"    gridline-color: #fffff8;\n"
"\n"
"	border-radius:0px;\n"
"	border-radius:0px;\n"
"\n"
"\n"
"\n"
"}\n"
"\n"
"QTableWidget QTableCornerButton::section {\n"
"    background-color: #646464;\n"
"	border-radius:0px;\n"
"\n"
"\n"
"}\n"
"\n"
"QTableView:item {\n"
"  border-bottom: 0.5px solid qlineargradient(spread:pad, x1:0, y1:1, x2:0, y2:0, stop:0 rgba(0, 0, 0, 0), stop:0.45677 rgba(0, 0, 0, 0), stop:0.479846 rgba(255, 255, 255, 255), stop:0.50571 rgba(239, 236, 55, 0), stop:1 rgba(239, 236, 55, 0));\n"
"	border-radius:0px;\n"
"\n"
"}\n"
"\n"
"QTableView::item:selected{\n"
"	\n"
"	border:1px solid rgb(92, 155, 179);\n"
"	color: rgb(255, 255, 255);\n"
"\n"
"}\n"
"")
        self.tableWidget.setAlternatingRowColors(False)
        self.tableWidget.setIconSize(QSize(40, 40))
        self.tableWidget.setShowGrid(False)
        self.tableWidget.horizontalHeader().setVisible(False)
        self.tableWidget.horizontalHeader().setCascadingSectionResizes(False)
        self.tableWidget.horizontalHeader().setDefaultSectionSize(114)
        self.tableWidget.horizontalHeader().setProperty("showSortIndicator", False)
        self.tableWidget.horizontalHeader().setStretchLastSection(True)
        self.tableWidget.verticalHeader().setVisible(False)

        self.horizontalLayout_54.addWidget(self.tableWidget)

        self.live_feed_table_area.addWidget(self.live_feed_table_card)

        self.horizontalLayout_53.addWidget(self.live_feed_table_area)


        self.verticalLayout_62.addWidget(self.live_feed_and_alerts)


        self.verticalLayout_92.addWidget(self.frame_57)


        self.verticalLayout_61.addWidget(self.frame_93)

        self.scrollArea_7.setWidget(self.scrollAreaWidgetContents_7)

        self.verticalLayout_60.addWidget(self.scrollArea_7)


        self.verticalLayout_59.addWidget(self.frame_56)


        self.verticalLayout_141.addWidget(self.frame_55)


        self.verticalLayout_140.addWidget(self.live_network_feed_card)

        icon8 = QIcon()
        icon8.addFile(u":/icons-cards/src-page-cartoes/null.png", QSize(), QIcon.Normal, QIcon.Off)
        self.live_area_chart.addTab(self.page_Tabe_main1, icon8, "")
        self.alert_area = QWidget()
        self.alert_area.setObjectName(u"alert_area")
        self.alert_area.setStyleSheet(u"background-color: rgba(255, 255, 255, 0); ")
        self.alert_table = QTableWidget(self.alert_area)
        if (self.alert_table.columnCount() < 3):
            self.alert_table.setColumnCount(3)
        __qtablewidgetitem8 = QTableWidgetItem()
        self.alert_table.setHorizontalHeaderItem(0, __qtablewidgetitem8)
        __qtablewidgetitem9 = QTableWidgetItem()
        self.alert_table.setHorizontalHeaderItem(1, __qtablewidgetitem9)
        __qtablewidgetitem10 = QTableWidgetItem()
        self.alert_table.setHorizontalHeaderItem(2, __qtablewidgetitem10)
        self.alert_table.setObjectName(u"alert_table")
        self.alert_table.setGeometry(QRect(3, 0, 1461, 522))
        self.alert_table.setMaximumSize(QSize(16777215, 16777215))
        self.alert_table.setFont(font)
        self.alert_table.setStyleSheet(u"QWidget {\n"
"	\n"
"    color: #fffff8;\n"
"	border-radius:0px;\n"
"\n"
"\n"
"\n"
"}\n"
"\n"
"QHeaderView::section {\n"
"    background-color: rgb(53, 53, 53);\n"
"	border:none;\n"
"	width:45px;\n"
"	height: 50px;\n"
"	margin-left:1px;\n"
"\n"
"	border-radius:0px;\n"
"\n"
"\n"
"}\n"
"\n"
"QTableWidget {\n"
"    gridline-color: #fffff8;\n"
"\n"
"	border-radius:0px;\n"
"	border-radius:0px;\n"
"\n"
"\n"
"\n"
"}\n"
"\n"
"QTableWidget QTableCornerButton::section {\n"
"    background-color: #646464;\n"
"	border-radius:0px;\n"
"\n"
"\n"
"}\n"
"\n"
"QTableView:item {\n"
"  border-bottom: 0.5px solid qlineargradient(spread:pad, x1:0, y1:1, x2:0, y2:0, stop:0 rgba(0, 0, 0, 0), stop:0.45677 rgba(0, 0, 0, 0), stop:0.479846 rgba(255, 255, 255, 255), stop:0.50571 rgba(239, 236, 55, 0), stop:1 rgba(239, 236, 55, 0));\n"
"	border-radius:0px;\n"
"\n"
"}\n"
"\n"
"QTableView::item:selected{\n"
"	\n"
"	border:1px solid rgb(92, 155, 179);\n"
"	color: rgb(255, 255, 255);\n"
"\n"
"}\n"
"")
        self.alert_table.setAlternatingRowColors(False)
        self.alert_table.setIconSize(QSize(40, 40))
        self.alert_table.setShowGrid(False)
        self.alert_table.horizontalHeader().setVisible(False)
        self.alert_table.horizontalHeader().setCascadingSectionResizes(False)
        self.alert_table.horizontalHeader().setDefaultSectionSize(114)
        self.alert_table.horizontalHeader().setProperty("showSortIndicator", False)
        self.alert_table.horizontalHeader().setStretchLastSection(True)
        self.alert_table.verticalHeader().setVisible(False)
        icon9 = QIcon()
        icon9.addFile(u":/icons-cards/src-page-cartoes/urgencia.png", QSize(), QIcon.Normal, QIcon.Off)
        self.live_area_chart.addTab(self.alert_area, icon9, "")

        self.verticalLayout_56.addWidget(self.live_area_chart)


        self.verticalLayout_10.addWidget(self.live_area)

        self.scrollArea_9.setWidget(self.scrollAreaWidgetContents_9)

        self.horizontalLayout_121.addWidget(self.scrollArea_9)

        self.horizontalSpacer_37 = QSpacerItem(0, 20, QSizePolicy.Preferred, QSizePolicy.Minimum)

        self.horizontalLayout_121.addItem(self.horizontalSpacer_37)

        self.dashboard_card.addWidget(self.dashboard_cards_2)

        self.horizontalLayout_51.addWidget(self.dashboard_card)

        self.scrollArea_6.setWidget(self.scrollAreaWidgetContents_6)

        self.horizontalLayout_50.addWidget(self.scrollArea_6)


        self.verticalLayout_33.addWidget(self.frame_42)


        self.verticalLayout_2.addWidget(self.frame_40)

        self.stackedWidget_2.addWidget(self.page_1)
        self.page_6 = QWidget()
        self.page_6.setObjectName(u"page_6")
        self.page_6.setStyleSheet(u"background-color: rgb(51, 51, 51);")
        self.frame_43 = QFrame(self.page_6)
        self.frame_43.setObjectName(u"frame_43")
        self.frame_43.setGeometry(QRect(80, 50, 781, 781))
        self.frame_43.setStyleSheet(u"background-color:rgba(255,255,255,30);")
        self.frame_43.setFrameShape(QFrame.StyledPanel)
        self.frame_43.setFrameShadow(QFrame.Raised)
        self.verticalLayout_3 = QVBoxLayout(self.frame_43)
        self.verticalLayout_3.setSpacing(15)
        self.verticalLayout_3.setObjectName(u"verticalLayout_3")
        self.verticalLayout_3.setContentsMargins(40, 40, 40, 40)
        self.frame_119 = QFrame(self.frame_43)
        self.frame_119.setObjectName(u"frame_119")
        self.frame_119.setStyleSheet(u"background-color:rgba(255,255,255,30);")
        self.frame_119.setFrameShape(QFrame.StyledPanel)
        self.frame_119.setFrameShadow(QFrame.Raised)
        self.verticalLayout_9 = QVBoxLayout(self.frame_119)
        self.verticalLayout_9.setSpacing(12)
        self.verticalLayout_9.setObjectName(u"verticalLayout_9")
        self.verticalLayout_9.setContentsMargins(25, 25, 25, 25)
        self.label_118 = QLabel(self.frame_119)
        self.label_118.setObjectName(u"label_118")
        self.label_118.setMaximumSize(QSize(16777215, 40))
        self.label_118.setMargin(5)

        self.verticalLayout_9.addWidget(self.label_118)

        self.current_username = QLineEdit(self.frame_119)
        self.current_username.setObjectName(u"current_username")
        self.current_username.setMinimumSize(QSize(0, 0))
        self.current_username.setMaximumSize(QSize(16777215, 16777215))
        self.current_username.setFont(font1)
        self.current_username.setAutoFillBackground(False)
        self.current_username.setStyleSheet(u"")
        self.current_username.setMaxLength(35)

        self.verticalLayout_9.addWidget(self.current_username)

        self.new_username = QLineEdit(self.frame_119)
        self.new_username.setObjectName(u"new_username")
        self.new_username.setMinimumSize(QSize(0, 0))
        self.new_username.setMaximumSize(QSize(16777215, 16777215))
        self.new_username.setFont(font1)
        self.new_username.setAutoFillBackground(False)
        self.new_username.setStyleSheet(u"")
        self.new_username.setMaxLength(35)

        self.verticalLayout_9.addWidget(self.new_username)

        self.current_password = QLineEdit(self.frame_119)
        self.current_password.setObjectName(u"current_password")
        self.current_password.setMinimumSize(QSize(0, 0))
        self.current_password.setMaximumSize(QSize(16777215, 16777215))
        self.current_password.setFont(font)
        self.current_password.setStyleSheet(u"")
        self.current_password.setMaxLength(32767)
        self.current_password.setFrame(True)
        self.current_password.setEchoMode(QLineEdit.Password)

        self.verticalLayout_9.addWidget(self.current_password)

        self.new_password = QLineEdit(self.frame_119)
        self.new_password.setObjectName(u"new_password")
        self.new_password.setMinimumSize(QSize(0, 0))
        self.new_password.setMaximumSize(QSize(16777215, 16777215))
        self.new_password.setFont(font)
        self.new_password.setStyleSheet(u"")
        self.new_password.setMaxLength(32767)
        self.new_password.setFrame(True)
        self.new_password.setEchoMode(QLineEdit.Password)

        self.verticalLayout_9.addWidget(self.new_password)

        self.frame_120 = QFrame(self.frame_119)
        self.frame_120.setObjectName(u"frame_120")
        self.frame_120.setStyleSheet(u"background-color:rgba(255,255,255,0);")
        self.frame_120.setFrameShape(QFrame.StyledPanel)
        self.frame_120.setFrameShadow(QFrame.Raised)
        self.verticalLayout_131 = QVBoxLayout(self.frame_120)
        self.verticalLayout_131.setSpacing(0)
        self.verticalLayout_131.setObjectName(u"verticalLayout_131")
        self.verticalLayout_131.setContentsMargins(0, 0, 0, 0)
        self.frame_121 = QFrame(self.frame_120)
        self.frame_121.setObjectName(u"frame_121")
        self.frame_121.setFrameShape(QFrame.StyledPanel)
        self.frame_121.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_127 = QHBoxLayout(self.frame_121)
        self.horizontalLayout_127.setSpacing(0)
        self.horizontalLayout_127.setObjectName(u"horizontalLayout_127")
        self.horizontalLayout_127.setContentsMargins(0, 0, 0, 0)
        self.horizontalSpacer_49 = QSpacerItem(70, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.horizontalLayout_127.addItem(self.horizontalSpacer_49)

        self.update_user_config_button = QPushButton(self.frame_121)
        self.update_user_config_button.setObjectName(u"update_user_config_button")
        self.update_user_config_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.update_user_config_button.setAutoFillBackground(False)

        self.horizontalLayout_127.addWidget(self.update_user_config_button)

        self.horizontalSpacer_50 = QSpacerItem(70, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.horizontalLayout_127.addItem(self.horizontalSpacer_50)


        self.verticalLayout_131.addWidget(self.frame_121)


        self.verticalLayout_9.addWidget(self.frame_120)


        self.verticalLayout_3.addWidget(self.frame_119)

        self.frame_112 = QFrame(self.frame_43)
        self.frame_112.setObjectName(u"frame_112")
        self.frame_112.setStyleSheet(u"background-color:rgba(255,255,255,30);")
        self.frame_112.setFrameShape(QFrame.StyledPanel)
        self.frame_112.setFrameShadow(QFrame.Raised)
        self.verticalLayout_129 = QVBoxLayout(self.frame_112)
        self.verticalLayout_129.setSpacing(12)
        self.verticalLayout_129.setObjectName(u"verticalLayout_129")
        self.verticalLayout_129.setContentsMargins(25, 25, 25, 25)
        self.label_117 = QLabel(self.frame_112)
        self.label_117.setObjectName(u"label_117")
        self.label_117.setMaximumSize(QSize(16777215, 40))
        self.label_117.setMargin(5)

        self.verticalLayout_129.addWidget(self.label_117)

        self.email_address_area_4 = QTextEdit(self.frame_112)
        self.email_address_area_4.setObjectName(u"email_address_area_4")

        self.verticalLayout_129.addWidget(self.email_address_area_4)

        self.frame_117 = QFrame(self.frame_112)
        self.frame_117.setObjectName(u"frame_117")
        self.frame_117.setStyleSheet(u"background-color:rgba(255,255,255,0);")
        self.frame_117.setFrameShape(QFrame.StyledPanel)
        self.frame_117.setFrameShadow(QFrame.Raised)
        self.verticalLayout_130 = QVBoxLayout(self.frame_117)
        self.verticalLayout_130.setSpacing(0)
        self.verticalLayout_130.setObjectName(u"verticalLayout_130")
        self.verticalLayout_130.setContentsMargins(0, 0, 0, 0)
        self.frame_118 = QFrame(self.frame_117)
        self.frame_118.setObjectName(u"frame_118")
        self.frame_118.setFrameShape(QFrame.StyledPanel)
        self.frame_118.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_126 = QHBoxLayout(self.frame_118)
        self.horizontalLayout_126.setSpacing(0)
        self.horizontalLayout_126.setObjectName(u"horizontalLayout_126")
        self.horizontalLayout_126.setContentsMargins(0, 0, 0, 0)
        self.horizontalSpacer_47 = QSpacerItem(70, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.horizontalLayout_126.addItem(self.horizontalSpacer_47)

        self.add_email_address_button_4 = QPushButton(self.frame_118)
        self.add_email_address_button_4.setObjectName(u"add_email_address_button_4")
        self.add_email_address_button_4.setCursor(QCursor(Qt.PointingHandCursor))

        self.horizontalLayout_126.addWidget(self.add_email_address_button_4)

        self.horizontalSpacer_48 = QSpacerItem(70, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.horizontalLayout_126.addItem(self.horizontalSpacer_48)


        self.verticalLayout_130.addWidget(self.frame_118)


        self.verticalLayout_129.addWidget(self.frame_117)


        self.verticalLayout_3.addWidget(self.frame_112)

        self.frame_106 = QFrame(self.frame_43)
        self.frame_106.setObjectName(u"frame_106")
        self.frame_106.setStyleSheet(u"background-color:rgba(255,255,255,30);")
        self.frame_106.setFrameShape(QFrame.StyledPanel)
        self.frame_106.setFrameShadow(QFrame.Raised)
        self.verticalLayout_119 = QVBoxLayout(self.frame_106)
        self.verticalLayout_119.setSpacing(12)
        self.verticalLayout_119.setObjectName(u"verticalLayout_119")
        self.verticalLayout_119.setContentsMargins(25, 25, 25, 25)
        self.label_112 = QLabel(self.frame_106)
        self.label_112.setObjectName(u"label_112")
        self.label_112.setMaximumSize(QSize(16777215, 40))
        self.label_112.setMargin(5)

        self.verticalLayout_119.addWidget(self.label_112)

        self.frame_107 = QFrame(self.frame_106)
        self.frame_107.setObjectName(u"frame_107")
        self.frame_107.setStyleSheet(u"background-color:rgba(255,255,255,0);")
        self.frame_107.setFrameShape(QFrame.StyledPanel)
        self.frame_107.setFrameShadow(QFrame.Raised)
        self.verticalLayout_122 = QVBoxLayout(self.frame_107)
        self.verticalLayout_122.setSpacing(0)
        self.verticalLayout_122.setObjectName(u"verticalLayout_122")
        self.verticalLayout_122.setContentsMargins(0, 0, 0, 0)
        self.frame_108 = QFrame(self.frame_107)
        self.frame_108.setObjectName(u"frame_108")
        self.frame_108.setFrameShape(QFrame.StyledPanel)
        self.frame_108.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_122 = QHBoxLayout(self.frame_108)
        self.horizontalLayout_122.setSpacing(0)
        self.horizontalLayout_122.setObjectName(u"horizontalLayout_122")
        self.horizontalLayout_122.setContentsMargins(0, 0, 0, 0)
        self.horizontalSpacer_38 = QSpacerItem(70, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.horizontalLayout_122.addItem(self.horizontalSpacer_38)

        self.monthly = QRadioButton(self.frame_108)
        self.monthly.setObjectName(u"monthly")
        font2 = QFont()
        font2.setFamily(u"Bahnschrift Light Condensed")
        font2.setPointSize(14)
        font2.setBold(False)
        font2.setItalic(False)
        font2.setWeight(3)
        font2.setStyleStrategy(QFont.PreferDefault)
        self.monthly.setFont(font2)
        self.monthly.setContextMenuPolicy(Qt.DefaultContextMenu)
        self.monthly.setLayoutDirection(Qt.LeftToRight)
        self.monthly.setStyleSheet(u"background-color:rgba(255,255,255,30);\n"
"color: rgb(255, 255, 255);")
        self.monthly.setChecked(True)

        self.horizontalLayout_122.addWidget(self.monthly)

        self.horizontalSpacer_39 = QSpacerItem(70, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.horizontalLayout_122.addItem(self.horizontalSpacer_39)

        self.quaterly = QRadioButton(self.frame_108)
        self.quaterly.setObjectName(u"quaterly")
        self.quaterly.setStyleSheet(u"background-color:rgba(255,255,255,30);\n"
"color: rgb(255, 255, 255);")
        self.quaterly.setChecked(False)

        self.horizontalLayout_122.addWidget(self.quaterly)

        self.horizontalSpacer_40 = QSpacerItem(70, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.horizontalLayout_122.addItem(self.horizontalSpacer_40)

        self.yearly = QRadioButton(self.frame_108)
        self.yearly.setObjectName(u"yearly")
        self.yearly.setStyleSheet(u"background-color:rgba(255,255,255,30);\n"
"color: rgb(255, 255, 255);")

        self.horizontalLayout_122.addWidget(self.yearly)


        self.verticalLayout_122.addWidget(self.frame_108)


        self.verticalLayout_119.addWidget(self.frame_107)


        self.verticalLayout_3.addWidget(self.frame_106)

        self.error_popup_2 = QFrame(self.page_6)
        self.error_popup_2.setObjectName(u"error_popup_2")
        self.error_popup_2.setGeometry(QRect(80, 10, 781, 25))
        self.error_popup_2.setMaximumSize(QSize(16777215, 16777215))
        self.error_popup_2.setStyleSheet(u"border-radius: 5px;\n"
"background-color: rgb(255, 0, 0);\n"
"")
        self.error_popup_2.setFrameShape(QFrame.StyledPanel)
        self.error_popup_2.setFrameShadow(QFrame.Raised)
        self.horizontalLayout_10 = QHBoxLayout(self.error_popup_2)
        self.horizontalLayout_10.setSpacing(6)
        self.horizontalLayout_10.setObjectName(u"horizontalLayout_10")
        self.horizontalLayout_10.setContentsMargins(10, 3, 10, 3)
        self.error_text_2 = QLabel(self.error_popup_2)
        self.error_text_2.setObjectName(u"error_text_2")
        self.error_text_2.setMinimumSize(QSize(300, 0))
        self.error_text_2.setFont(font)
        self.error_text_2.setStyleSheet(u"border-style: none;\n"
"background-color: rgb(255, 0, 0);\n"
"border-radius: 5px;")
        self.error_text_2.setAlignment(Qt.AlignCenter)

        self.horizontalLayout_10.addWidget(self.error_text_2)

        self.cancel_error_popup_2 = QPushButton(self.error_popup_2)
        self.cancel_error_popup_2.setObjectName(u"cancel_error_popup_2")
        self.cancel_error_popup_2.setMinimumSize(QSize(0, 20))
        self.cancel_error_popup_2.setMaximumSize(QSize(28, 35))
        self.cancel_error_popup_2.setStyleSheet(u"QPushButton {\n"
"	border-radius: 5px;\n"
"	border-image: url(:/newPrefix/cancel.png);\n"
"	background-position: center;\n"
"	border-style: solid;\n"
"	border-color: white;\n"
"	border-width: 2px;\n"
"	\n"
"	\n"
"\n"
"}\n"
"\n"
"QPushButton:hover {\n"
"	\n"
"	background-color: rgb(50, 50, 50);\n"
"	color:rgb(202, 202, 202);\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"	\n"
"	background-color: rgb(34, 34, 34);\n"
"	color:rgb(202, 202, 202);\n"
"	border: 2px solid rgb(55,55,55)\n"
"}")

        self.horizontalLayout_10.addWidget(self.cancel_error_popup_2)

        self.stackedWidget_2.addWidget(self.page_6)

        self.horizontalLayout_6.addWidget(self.stackedWidget_2)


        self.verticalLayout_7.addWidget(self.group)

        self.stackedWidget.addWidget(self.main)

        self.verticalLayout_8.addWidget(self.stackedWidget)

        MainWindow.setCentralWidget(self.centralwidget)
        QWidget.setTabOrder(self.user_name, self.password)
        QWidget.setTabOrder(self.password, self.show_password_check_box)
        QWidget.setTabOrder(self.show_password_check_box, self.login_button)
        QWidget.setTabOrder(self.login_button, self.minimize)
        QWidget.setTabOrder(self.minimize, self.maxmize)
        QWidget.setTabOrder(self.maxmize, self.exit)

        self.retranslateUi(MainWindow)

        self.stackedWidget.setCurrentIndex(0)
        self.stackedWidget_2.setCurrentIndex(0)
        self.dashboard_card.setCurrentIndex(0)
        self.dashboard_control_area.setCurrentIndex(0)
        self.live_area_chart.setCurrentIndex(0)
        self.live_feed_table_area.setCurrentIndex(0)


        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"AEGIS", None))
        self.actionSalvar_automaticamente.setText(QCoreApplication.translate("MainWindow", u"Salvar automaticamente", None))
        self.actionAtualizar_automaticamente.setText(QCoreApplication.translate("MainWindow", u"Atualizar automaticamente", None))
        self.actionAbrir_DB.setText(QCoreApplication.translate("MainWindow", u"Abrir DB", None))
        self.actionSalvar_Relatorio.setText(QCoreApplication.translate("MainWindow", u"Salvar Relatorio", None))
        self.actionAbrir_xlsx.setText(QCoreApplication.translate("MainWindow", u"Abrir xlsx", None))
        self.actionImportar_xlsx.setText(QCoreApplication.translate("MainWindow", u"Importar xlsx", None))
        self.error_text.setText(QCoreApplication.translate("MainWindow", u"Error", None))
        self.cancel_error_popup.setText("")
        self.user_name.setText("")
        self.user_name.setPlaceholderText(QCoreApplication.translate("MainWindow", u"   Username", None))
        self.password.setPlaceholderText(QCoreApplication.translate("MainWindow", u"   Password", None))
        self.show_password_check_box.setText(QCoreApplication.translate("MainWindow", u"Show Password", None))
        self.login_button.setText(QCoreApplication.translate("MainWindow", u"Enter", None))
        self.minimize.setText("")
        self.maxmize.setText("")
        self.exit.setText("")
        self.menu_button.setText(QCoreApplication.translate("MainWindow", u"    Menu", None))
        self.home_button.setText(QCoreApplication.translate("MainWindow", u"     Home", None))
        self.settings_button.setText(QCoreApplication.translate("MainWindow", u"     Settings", None))
        self.logs_button.setText(QCoreApplication.translate("MainWindow", u"    Logs", None))
        self.logout_button.setText(QCoreApplication.translate("MainWindow", u"    Log Out", None))
        self.exit_button.setText(QCoreApplication.translate("MainWindow", u"    Exit", None))
        self.user_name_info.setText(QCoreApplication.translate("MainWindow", u"User Name", None))
        self.label_42.setText(QCoreApplication.translate("MainWindow", u"15:23", None))
        self.cpu_label.setText(QCoreApplication.translate("MainWindow", u"CPU", None))
        self.cpu_usage_label.setText(QCoreApplication.translate("MainWindow", u"0% Usage", None))
        self.cpu_frequency_label.setText(QCoreApplication.translate("MainWindow", u"0 GHz", None))
        self.memory_label.setText(QCoreApplication.translate("MainWindow", u"Memory", None))
        self.memory_usage_label.setText(QCoreApplication.translate("MainWindow", u"0/0 GB (0%)", None))
        self.netwrok_label.setText(QCoreApplication.translate("MainWindow", u"Network", None))
        self.network_throughput_label.setText(QCoreApplication.translate("MainWindow", u"S: 0 Kbps", None))
        self.network_throughput_label_2.setText(QCoreApplication.translate("MainWindow", u"R: 0 Kbps", None))
        self.power_button.setText("")
        self.label_67.setText(QCoreApplication.translate("MainWindow", u"Dashboard", None))
        ___qtablewidgetitem = self.tableWidget.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(QCoreApplication.translate("MainWindow", u"Source IP", None));
        ___qtablewidgetitem1 = self.tableWidget.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(QCoreApplication.translate("MainWindow", u"Destination IP", None));
        ___qtablewidgetitem2 = self.tableWidget.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(QCoreApplication.translate("MainWindow", u"Source Port", None));
        ___qtablewidgetitem3 = self.tableWidget.horizontalHeaderItem(3)
        ___qtablewidgetitem3.setText(QCoreApplication.translate("MainWindow", u"Destination Port", None));
        ___qtablewidgetitem4 = self.tableWidget.horizontalHeaderItem(4)
        ___qtablewidgetitem4.setText(QCoreApplication.translate("MainWindow", u"Protocol", None));
        ___qtablewidgetitem5 = self.tableWidget.horizontalHeaderItem(5)
        ___qtablewidgetitem5.setText(QCoreApplication.translate("MainWindow", u"TCP Flags", None));
        ___qtablewidgetitem6 = self.tableWidget.horizontalHeaderItem(6)
        ___qtablewidgetitem6.setText(QCoreApplication.translate("MainWindow", u"InByte", None));
        ___qtablewidgetitem7 = self.tableWidget.horizontalHeaderItem(7)
        ___qtablewidgetitem7.setText(QCoreApplication.translate("MainWindow", u"OutByte", None));
        self.live_area_chart.setTabText(self.live_area_chart.indexOf(self.page_Tabe_main1), QCoreApplication.translate("MainWindow", u"Live Network Feed", None))
        ___qtablewidgetitem8 = self.alert_table.horizontalHeaderItem(0)
        ___qtablewidgetitem8.setText(QCoreApplication.translate("MainWindow", u"Timestamp", None));
        ___qtablewidgetitem9 = self.alert_table.horizontalHeaderItem(1)
        ___qtablewidgetitem9.setText(QCoreApplication.translate("MainWindow", u"Alert Message", None));
        ___qtablewidgetitem10 = self.alert_table.horizontalHeaderItem(2)
        ___qtablewidgetitem10.setText(QCoreApplication.translate("MainWindow", u"Risk Level", None));
        self.live_area_chart.setTabText(self.live_area_chart.indexOf(self.alert_area), QCoreApplication.translate("MainWindow", u"Alerts", None))
        self.label_118.setText(QCoreApplication.translate("MainWindow", u"<html><head/><body><p align=\"center\"><span style=\" color:#ffffff;\">User Config</span></p></body></html>", None))
        self.current_username.setText("")
        self.current_username.setPlaceholderText(QCoreApplication.translate("MainWindow", u"  Current Username", None))
        self.new_username.setText("")
        self.new_username.setPlaceholderText(QCoreApplication.translate("MainWindow", u"  New Username", None))
        self.current_password.setPlaceholderText(QCoreApplication.translate("MainWindow", u"  Current Password", None))
        self.new_password.setPlaceholderText(QCoreApplication.translate("MainWindow", u"  New Password", None))
        self.update_user_config_button.setText(QCoreApplication.translate("MainWindow", u"Update", None))
        self.label_117.setText(QCoreApplication.translate("MainWindow", u"<html><head/><body><p align=\"center\"><span style=\" color:#ffffff;\">Alert Emails</span></p></body></html>", None))
        self.email_address_area_4.setPlaceholderText(QCoreApplication.translate("MainWindow", u" Add emails for sending alerts seperated by commas", None))
        self.add_email_address_button_4.setText(QCoreApplication.translate("MainWindow", u"Add", None))
        self.label_112.setText(QCoreApplication.translate("MainWindow", u"<html><head/><body><p align=\"center\"><span style=\" color:#ffffff;\">Log Files Duration</span></p></body></html>", None))
        self.monthly.setText(QCoreApplication.translate("MainWindow", u"Monthly", None))
        self.quaterly.setText(QCoreApplication.translate("MainWindow", u"Quaterly", None))
        self.yearly.setText(QCoreApplication.translate("MainWindow", u"Yearly", None))
        self.error_text_2.setText(QCoreApplication.translate("MainWindow", u"Error", None))
        self.cancel_error_popup_2.setText("")
    # retranslateUi

