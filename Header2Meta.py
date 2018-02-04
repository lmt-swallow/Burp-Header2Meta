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
        self._scope = ArrayList()
        ## User-defined
        self._header_source_regex = re.compile(".*", re.MULTILINE)
        self._where_to_insert_regex = re.compile("<head.*?>")
        self._csrf_token = ""



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
        # only process requests/responses in the scope
        if not self.isInScope(self._helpers.analyzeRequest(messageInfo).getUrl()):
            return

        # only process if tools are in the setting
        if not self._checkboxes[toolFlag].isSelected():
            return None

        # Intercept and modify only responses
        if not messageIsRequest:
            responseInfo = self._helpers.analyzeRequest(messageInfo.getResponse())

            filtered_headers = map(lambda x: '<meta name="{0}" content="{1}">'.format(x[0].strip(),x[1][1:]),\
                                   filter(lambda x: self._header_source_regex.search(x[0].strip()) != None,\
                                          map(lambda x: x.split(':'), responseInfo.getHeaders()[1:])))

            body = self._helpers.bytesToString(messageInfo.getResponse()[responseInfo.getBodyOffset():]).encode('utf-8')
            
            index_to_insert = self._where_to_insert_regex.search(body).end()
            body = body[:index_to_insert] + ''.join(filtered_headers) + body[index_to_insert:]
            
            updatedResponse = self._helpers.buildHttpMessage(responseInfo.getHeaders(), body.decode('utf-8'))
            messageInfo.setResponse(updatedResponse)

    # Utilities
    def updateHeaderSourceRegex(self, e): 
        self._header_source_regex = re.compile(self._form_header_regex.getText(), re.MULTILINE)
        self._label_header_regex_now_2.setText(self._header_source_regex.pattern)
        
    def updateInsertionPointRegex(self, e):
        self._where_to_insert_regex = re.compile(self._form_insertion_regex.getText(), re.MULTILINE)
        self._label_insertion_regex_now_2.setText(self._where_to_insert_regex.pattern)
        
    def addURLDirectly(self, e):
        row = self._scope.size()
        self._scope.add(ScopeInfo(self._form_add_url.getText(),
                                  re.compile(self._form_add_url.getText(), re.MULTILINE)))
        self._form_add_url.setText("")
        self.fireTableRowsInserted(row, row)

    def isInScope(self, url):
        for inscope in self._scope:
            if inscope.regex.search(str(url)):
                return True
        return False
    
    def removeFromScope(self, invocation):
        index_to_delete = self._url_table.getSelectedRow()
        self._scope.pop(index_to_delete)
        self.fireTableRowsDeleted(index_to_delete, index_to_delete)

    def addToScope(self, invocation):
        messagesInfo = self._add_invocation.getSelectedMessages()
        row = self._scope.size()
        for messageInfo in messagesInfo:
            self._scope.add(ScopeInfo(self._helpers.analyzeRequest(messageInfo).getUrl()))
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
            return self._scope.size()
        except:
            return 0

    def getColumnCount(self):
        return 1

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "URL Regex"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        if columnIndex == 0:
            return self._scope.get(rowIndex).regex.pattern
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
        self._label_header_regex_now_1 = JLabel("(1) Regex for headers you want to extract to meta tag: ")
        self._label_header_regex_now_2 = JLabel(self._header_source_regex.pattern)
        self._label_header_regex = JLabel("(1) New Regex:")
        self._form_header_regex = JTextField(self._header_source_regex.pattern, 64)
        self._button_header_regex = JButton('Update', actionPerformed=self.updateHeaderSourceRegex)        

        self._label_insertion_regex_now_1 = JLabel("(2) Regex for insert point you want to extract to meta tag: ")
        self._label_insertion_regex_now_2 = JLabel(self._where_to_insert_regex.pattern)
        self._label_insertion_regex = JLabel("(2) New Regex:")
        self._form_insertion_regex = JTextField(self._where_to_insert_regex.pattern, 64)
        self._button_insertion_regex = JButton('Update', actionPerformed=self.updateInsertionPointRegex)        

        self._label_add_url = JLabel("(3) Add This URL: ")
        self._form_add_url = JTextField("", 64)
        self._button_add_url = JButton('Add', actionPerformed=self.addURLDirectly)

        checkboxes_components = {0: dict(zip(range(0,len(self._checkboxes)), self._checkboxes.values()))}
        ## logate regex settings
        ui_components_for_settings_pane = {
            0: { 0: self._label_header_regex_now_1, 1: self._label_header_regex_now_2 },
            1: { 0: self._label_header_regex, 1: self._form_header_regex, 2: self._button_header_regex},
            2: { 0: self._label_insertion_regex_now_1, 1: self._label_insertion_regex_now_2 },
            3: { 0: self._label_insertion_regex, 1: self._form_insertion_regex, 2: self._button_insertion_regex},
            4: { 0: self._label_add_url, 1: self._form_add_url, 2: self._button_add_url},
            5: { 0: {'item': self.compose_ui(checkboxes_components), 'width': 3} }
        }
        # build a split panel & set UI component
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane.setResizeWeight(0.8)
        self._splitpane.setLeftComponent(scrollPane)
        self._splitpane.setRightComponent(self.compose_ui(ui_components_for_settings_pane))
        self._callbacks.customizeUiComponent(self._splitpane)
     
    def compose_ui(self, components):
        panel = JPanel() 
        panel.setLayout(GridBagLayout())
        constraints= GridBagConstraints()
        constraints.fill = GridBagConstraints.HORIZONTAL
        for i in components:
            for j in components[i]:
                constraints.gridy, constraints.gridx = i, j
                constraints.gridwidth = components[i][j]['width'] if type(components[i][j]) == dict and 'width' in components[i][j] else 1
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
        ScopeInfo = self._extender._scope.get(row)
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
    def __init__(self, url, regex=None):
        self.url = url
        parsed_url = urlparse.urlparse(str(url))
        if regex == None:
            self.regex = re.compile("^{0}://{1}{2}.*".format(parsed_url.scheme, parsed_url.netloc, parsed_url.path), re.MULTILINE)
        else:
            self.regex = regex
