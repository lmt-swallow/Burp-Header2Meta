import re
from datetime import datetime
import urllib
import urlparse

from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IContextMenuFactory

from java.awt import Component
from java.awt import Point
from java.awt import Insets
from java.awt import GridBagLayout, GridBagConstraints
from java.awt.event import MouseAdapter, MouseEvent
from java.util import ArrayList
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTable;
from javax.swing import JPanel
from javax.swing import JMenuItem
from javax.swing import JPopupMenu
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JSeparator
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing.table import AbstractTableModel;


class BurpExtender(IBurpExtender, ITab, IHttpListener, AbstractTableModel, IContextMenuFactory):
    
    #
    # implement IBurpExtender
    #
    
    def registerExtenderCallbacks(self, callbacks):
        # set default values
        ## Pre-defined
        callbacks.setExtensionName("Header2Meta")
        self._imenu_description = "Add this URL to the scope of Header2Meta"
        self._remove_description = "Remove this URL from the scope"
        self._scopes = ArrayList()
        ## User-defined
        self._header_regex_default = re.compile(".*", re.MULTILINE)
        self._insertion_point_regex_default = re.compile("<head.*?>", re.MULTILINE)
        



        # store callbacks set an alias for stdout and helpers
        self._callbacks = callbacks
        self._out = callbacks.getStdout()
        self._helpers = callbacks.getHelpers()

        # initialize GUI
        callbacks.registerContextMenuFactory(self)
        self.initializeGUI()
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

      
    def log(self, message):
        self._out.write("[{0}] {1}\n".format(datetime.now().isoformat(),message))        
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process if tools are in the setting
        if not self._checkboxes[toolFlag].isSelected():
            return None

        request_url = self._helpers.analyzeRequest(messageInfo).getUrl()

        if not messageIsRequest:
            body = self._helpers.bytesToString(messageInfo.getResponse()).encode('utf-8')
            for scope in self._scopes:
                if not scope.isMatch(request_url): continue

                responseInfo = self._helpers.analyzeRequest(messageInfo.getResponse())

                filtered_headers = map(lambda x: '<meta name="{0}" content="{1}">'.format(x[0].strip(),x[1][1:]),\
                                       filter(lambda x: scope.header_regex.search(x[0].strip()) != None,\
                                              map(lambda x: x.split(':'), responseInfo.getHeaders()[1:])))

                body = self._helpers.bytesToString(messageInfo.getResponse()[responseInfo.getBodyOffset():]).encode('utf-8')
                
                index_to_insert = scope.insertion_point_regex.search(body).end()
                body = body[:index_to_insert] + ''.join(filtered_headers) + body[index_to_insert:]
                
                updatedResponse = self._helpers.buildHttpMessage(responseInfo.getHeaders(), body.decode('utf-8'))
                messageInfo.setResponse(updatedResponse)    



    # Utilities
    def updateHeadersRegex(self, e):
        row = self._url_table.getSelectedRow()
        if row == -1:
            return
        self._scopes[row].header_regex = re.compile(self._form_header_regex.getText(), re.MULTILINE)
        self._label_header_regex_now_2.setText(self._scopes[row].header_regex.pattern)
        self.fireTableRowsUpdated(row, row)

        
    def updateInsertionPointRegex(self, e):
        row = self._url_table.getSelectedRow()
        if row == -1:
            return
        self._scopes[row].insertion_point_regex = re.compile(self._form_insertion_point_regex.getText(), re.MULTILINE)
        self._label_insertion_point_regex_now_2.setText(self._scopes[row].insertion_point_regex.pattern)
        self.fireTableRowsUpdated(row, row)
        
    def addURLDirectly(self, e):
        row = self._scopes.size()
        self._scopes.add(ScopeInfo(self._form_add_url.getText(), self._header_regex_default, self._insertion_point_regex_default,
                                   url_regex = re.compile(self._form_add_url.getText(), re.MULTILINE)))
        self._form_add_url.setText("")
        self.fireTableRowsInserted(row, row)
    
    def removeFromScope(self, invocation):
        index_to_delete = self._url_table.getSelectedRow()
        self._scopes.pop(index_to_delete)
        self.fireTableRowsDeleted(index_to_delete, index_to_delete)

    def addToScope(self, invocation):
        messagesInfo = self._add_invocation.getSelectedMessages()
        row = self._scopes.size()
        for messageInfo in messagesInfo:
            self._scopes.add(ScopeInfo(self._helpers.analyzeRequest(messageInfo).getUrl(), self._header_regex_default, self._insertion_point_regex_default))
        self.fireTableRowsInserted(row, row)

    #
    # implement IContextMenuFactory
    #

    def createMenuItems(self, invocation):
        self._add_invocation = invocation
        self._imenu = JMenuItem(self._imenu_description, actionPerformed=self.addToScope)
        return [self._imenu]

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._scopes.size()
        except:
            return 0

    def getColumnCount(self):
        return 3

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "URL"
        if columnIndex == 1:
            return "Headers"
        if columnIndex == 2:
            return "Insertion Point"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        if columnIndex == 0:
            return self._scopes[rowIndex].url_regex.pattern
        if columnIndex == 1:
            return self._scopes[rowIndex].header_regex.pattern
        if columnIndex == 2:
            return self._scopes[rowIndex].insertion_point_regex.pattern
        return ""

    #
    # implement ITab
    #    

    def getTabCaption(self):
        return "Header2Meta"
    
    def getUiComponent(self):
        return self._splitpane

    #
    # GUI settings
    #

    def initializeGUI(self):
        # table panel of scope entries
        self._url_table = Table(self)
        table_popup = JPopupMenu();
        remove_item_menu = JMenuItem(self._remove_description, actionPerformed=self.removeFromScope)
        table_popup.add(remove_item_menu)
        self._url_table.setComponentPopupMenu(table_popup)
        self._url_table.addMouseListener(TableMouseListener(self._url_table))
        scrollPane = JScrollPane(self._url_table)

        # setting panel              

        ##  locate checkboxes
        ### for constants, see: https://portswigger.net/burp/extender/api/constant-values.html#burp.IBurpExtenderCallbacks.TOOL_PROXY          
        self._checkboxes = {
            2:    JCheckBox('Target'),
            4:    JCheckBox('Proxy'),
            8:    JCheckBox('Spider'),
            16:   JCheckBox('Scanner'),
            32:   JCheckBox('Intruder'),            
            64:   JCheckBox('Repeater'),
            128:  JCheckBox('Sequencer'),
            1024: JCheckBox('Extender')
        }
        checkboxes_components = {0: dict(zip(range(1,len(self._checkboxes)), self._checkboxes.values()))}

        self._label_header_regex_now_1 = JLabel("(1) Regex for headers you want to extract to meta tag: ")
        self._label_header_regex_now_2 = JLabel("")
        self._label_header_regex = JLabel("(1) New regex:")
        self._form_header_regex = JTextField("", 64)
        self._button_header_regex = JButton('Update', actionPerformed=self.updateHeadersRegex)        
        self._label_insertion_point_regex_now_1 = JLabel("(2) Regex for insert point you want to extract to meta tag: ")
        self._label_insertion_point_regex_now_2 = JLabel("")
        self._label_insertion_point_regex = JLabel("(2) New regex: ")
        self._form_insertion_point_regex = JTextField("", 64)
        self._button_insertion_point_regex = JButton('Update', actionPerformed=self.updateInsertionPointRegex)
        self._label_add_url = JLabel("Add this URL: ")
        self._form_add_url = JTextField("", 64)
        self._button_add_url = JButton('Add', actionPerformed=self.addURLDirectly)
                
        ## logate regex settings
        ui_components_for_settings_pane = {
            0: { 0: JLabel("Local Settings:") },
            1: { 0: self._label_header_regex_now_1, 1: self._label_header_regex_now_2 },
            2: { 0: self._label_header_regex, 1: self._form_header_regex, 2: self._button_header_regex},
            3: { 0: self._label_insertion_point_regex_now_1, 1: self._label_insertion_point_regex_now_2 },
            4: { 0: self._label_insertion_point_regex, 1: self._form_insertion_point_regex, 2: self._button_insertion_point_regex},
            5: { 0: {'item': JSeparator(JSeparator.HORIZONTAL), 'width': 3, }},
            6: { 0: JLabel("General Settings:") },
            7: { 0: self._label_add_url, 1: self._form_add_url, 2: self._button_add_url},
            8: { 0: JLabel("Use this extender in:"), 1: {'item': self.compose_ui(checkboxes_components), 'width': 3} }
        }
        # build a split panel & set UI component
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane.setResizeWeight(0.85)
        self._splitpane.setLeftComponent(scrollPane)
        self._splitpane.setRightComponent(self.compose_ui(ui_components_for_settings_pane))
        self._callbacks.customizeUiComponent(self._splitpane)
     
    def compose_ui(self, components):
        panel = JPanel() 
        panel.setLayout(GridBagLayout())
        constraints= GridBagConstraints()
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.insets = Insets(2, 1, 2, 1)
        for i in components:
            for j in components[i]:
                constraints.gridy, constraints.gridx = i, j
                constraints.gridwidth = components[i][j]['width'] if type(components[i][j]) == dict and 'width' in components[i][j] else 1
                constraints.gridheight = components[i][j]['height'] if type(components[i][j]) == dict and 'height' in components[i][j] else 1
                item = components[i][j]['item'] if type(components[i][j]) == dict and 'item' in components[i][j] else components[i][j]
                panel.add(item, constraints)
        return panel    


#
# Wrappers for JTable
#

class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)    
    def changeSelection(self, row, col, toggle, extend):    
        scopeInfo  = self._extender._scopes.get(row)
        self._extender._label_header_regex_now_2.setText(scopeInfo.header_regex.pattern)
        self._extender._form_header_regex.setText(scopeInfo.header_regex.pattern)
        self._extender._label_insertion_point_regex_now_2.setText(scopeInfo.insertion_point_regex.pattern)
        self._extender._form_insertion_point_regex.setText(scopeInfo.insertion_point_regex.pattern)
        
        JTable.changeSelection(self, row, col, toggle, extend)

class TableMouseListener(MouseAdapter):
    def __init__(self, table):
        self._table = table
    def mousePressed(self, event):
        point = event.getPoint()
        currentRow = self._table.rowAtPoint(point)
        self._table.setRowSelectionInterval(currentRow, currentRow)
    
#
# Scope definition (to be extended)
#

class ScopeInfo:
    def __init__(self, url, header_regex, insertion_point_regex, url_regex=None):
        self.url = url
        self.insertion_point_regex = insertion_point_regex
        self.header_regex = header_regex
        parsed_url = urlparse.urlparse(str(url))
        if url_regex == None:
            self.url_regex = re.compile("^{0}://{1}{2}.*".format(parsed_url.scheme, parsed_url.netloc, parsed_url.path), re.MULTILINE)
        else:
            self.url_regex = url_regex
    def isMatch(self, url):
        return self.url_regex.search(str(url)) != None
