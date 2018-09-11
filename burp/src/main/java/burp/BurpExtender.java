///////////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s):
//              Denim Group, Ltd.
//              Secure Decisions, a division of Applied Visions, Inc
//
////////////////////////////////////////////////////////////////////////

package burp;

import burp.custombutton.LocalEndpointsButton;
import burp.custombutton.SerializedEndpointsButton;
import burp.extention.BurpPropertiesManager;
import com.denimgroup.threadfix.data.entities.RouteParameter;
import com.denimgroup.threadfix.data.interfaces.Endpoint;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 12/30/13
 * Time: 2:28 PM
 * To change this template use File | Settings | File Templates.
 */
public class BurpExtender implements IBurpExtender, ITab
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JTabbedPane tabbedPane;
    private JTextField sourceFolderField;
    private JTextField oldSourceFolderField;
    private JTextField serializationField;
    private JTextField oldSerializationField;
    private JTextField configFileField;
    private JTextField targetHostField;
    private JTextField targetPathField;
    private JTextField targetPortField;
    private JCheckBox autoScanField;
    private JCheckBox autoSpiderField;
    private JCheckBox useHttpField;
    private JLabel profMessage;
    private JLabel autoScanText;
    //private JTextArea displayArea = new JTextArea();
    private JLabel displayArea = new JLabel();

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        BurpPropertiesManager.generateBurpPropertiesManager(callbacks);
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Attack Surface Detector");

        // create UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                tabbedPane = new JTabbedPane();

                JPanel mainPanel = buildMainPanel();
                JScrollPane mainScrollPane = new JScrollPane(mainPanel);
                tabbedPane.addTab("Main", null, mainScrollPane, "The main tab of the Attack Surface Detector which contains buttons to import endpoints and a table to view these endpoints");

                JPanel optionsPanel = buildOptionsPanel();
                JScrollPane optionsScrollPane = new JScrollPane(optionsPanel);
                tabbedPane.addTab("Options", null, optionsScrollPane, "This tab allows the user to alter the configuration of the Attack Surface Detector");
                tabbedPane.addTab("Help", null, buildHelpPanel(), "The information tab of the Attack Surface Detector which provides the user with useful information regarding supported formats and general usage");


                // customize our UI components
                callbacks.customizeUiComponent(tabbedPane);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    private JPanel buildMainPanel()
    {
        final JPanel mainPanel = new JPanel();

        mainPanel.setLayout(new GridBagLayout());
        Insets mainPanelInsets = new Insets(10, 10, 10, 10);
        int yPosition = 0;

        JPanel importExportPanel = buildImportExportPanel();
        GridBagConstraints importExportPanelConstraints = new GridBagConstraints();
        importExportPanelConstraints.gridx = 0;
        importExportPanelConstraints.gridy = yPosition++;
        importExportPanelConstraints.ipadx = 5;
        importExportPanelConstraints.ipady = 5;
        importExportPanelConstraints.insets = mainPanelInsets;
        importExportPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        mainPanel.add(importExportPanel, importExportPanelConstraints);

        JPanel endpointTablePane = buildEndpointsTable();
        callbacks.customizeUiComponent(endpointTablePane);

        JPanel displayPane = buildDisplayPane();
        callbacks.customizeUiComponent(displayPane);
        GridBagConstraints displayConstraints = new GridBagConstraints();
        displayConstraints.gridx = 0;
        displayConstraints.gridy = yPosition++;
        displayConstraints.insets = mainPanelInsets;
        displayConstraints.fill = GridBagConstraints.BOTH;
        displayConstraints.weightx = 1.0;
        displayConstraints.weighty = 1.0;
        displayConstraints.anchor = GridBagConstraints.NORTH;

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, endpointTablePane, displayPane);
        mainPanel.add(splitPane, displayConstraints);

        return mainPanel;
    }

    private JPanel buildOptionsPanel() {
        final JPanel optionsPanel = new JPanel();
        optionsPanel.addHierarchyListener(new HierarchyListener() {
            @Override
            public void hierarchyChanged(HierarchyEvent e) {
                boolean tabIsShowing = optionsPanel.isShowing();
                if (tabIsShowing) {
                    loadOptionsProperties();
                } else {
                    BurpPropertiesManager.getBurpPropertiesManager().saveProperties();
                }
            }
        });
        optionsPanel.setLayout(new GridBagLayout());
        Insets optionsPanelInsets = new Insets(10, 10, 10, 10);
        int yPosition = 0;

        JPanel autoOptionsPanel = buildAutoOptionsPanel();
        GridBagConstraints autoOptionsPanelConstraints = new GridBagConstraints();
        autoOptionsPanelConstraints.gridx = 0;
        autoOptionsPanelConstraints.gridy = yPosition++;
        autoOptionsPanelConstraints.ipadx = 5;
        autoOptionsPanelConstraints.ipady = 5;
        autoOptionsPanelConstraints.insets = optionsPanelInsets;
        autoOptionsPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        optionsPanel.add(autoOptionsPanel, autoOptionsPanelConstraints);

        JSeparator autoOptionsPanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        callbacks.customizeUiComponent(autoOptionsPanelSeparator);
        GridBagConstraints autoOptionsPanelSeparatorConstraints = new GridBagConstraints();
        autoOptionsPanelSeparatorConstraints.gridx = 0;
        autoOptionsPanelSeparatorConstraints.gridy = yPosition++;
        autoOptionsPanelSeparatorConstraints.insets = optionsPanelInsets;
        autoOptionsPanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        autoOptionsPanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        optionsPanel.add(autoOptionsPanelSeparator, autoOptionsPanelSeparatorConstraints);

        JPanel sourcePanel = buildSourcePanel();
        GridBagConstraints sourcePanelConstraints = new GridBagConstraints();
        sourcePanelConstraints.gridx = 0;
        sourcePanelConstraints.gridy = yPosition++;
        sourcePanelConstraints.ipadx = 5;
        sourcePanelConstraints.ipady = 5;
        sourcePanelConstraints.insets = optionsPanelInsets;
        sourcePanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        optionsPanel.add(sourcePanel, sourcePanelConstraints);

        JSeparator sourcePanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        callbacks.customizeUiComponent(sourcePanelSeparator);
        GridBagConstraints sourcePanelSeparatorConstraints = new GridBagConstraints();
        sourcePanelSeparatorConstraints.gridx = 0;
        sourcePanelSeparatorConstraints.gridy = yPosition++;
        sourcePanelSeparatorConstraints.insets = optionsPanelInsets;
        sourcePanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        sourcePanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        optionsPanel.add(sourcePanelSeparator, sourcePanelSeparatorConstraints);

        JPanel serializationPanel = buildSerializationPanel();
        GridBagConstraints serializationConstraints = new GridBagConstraints();
        serializationConstraints.gridx = 0;
        serializationConstraints.gridy = yPosition++;
        serializationConstraints.ipadx = 5;
        serializationConstraints.ipady = 5;
        serializationConstraints.insets = optionsPanelInsets;
        serializationConstraints.anchor = GridBagConstraints.NORTHWEST;
        optionsPanel.add(serializationPanel, serializationConstraints);

        JSeparator serializationPanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        callbacks.customizeUiComponent(serializationPanelSeparator);
        GridBagConstraints serializationPanelSeparatorConstraints = new GridBagConstraints();
        serializationPanelSeparatorConstraints.gridx = 0;
        serializationPanelSeparatorConstraints.gridy = yPosition++;
        serializationPanelSeparatorConstraints.insets = optionsPanelInsets;
        serializationPanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        serializationPanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        optionsPanel.add(serializationPanelSeparator, serializationPanelSeparatorConstraints);

        JPanel configPanel = buildConfigPanel();
        GridBagConstraints configPanelConstraints = new GridBagConstraints();
        configPanelConstraints.gridx = 0;
        configPanelConstraints.gridy = yPosition++;
        configPanelConstraints.ipadx = 5;
        configPanelConstraints.ipady = 5;
        configPanelConstraints.insets = optionsPanelInsets;
        configPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        optionsPanel.add(configPanel, configPanelConstraints);

        JSeparator configPanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        callbacks.customizeUiComponent(configPanelSeparator);
        GridBagConstraints configPanelSeparatorConstraints = new GridBagConstraints();
        configPanelSeparatorConstraints.gridx = 0;
        configPanelSeparatorConstraints.gridy = yPosition++;
        configPanelSeparatorConstraints.insets = optionsPanelInsets;
        configPanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        configPanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        optionsPanel.add(configPanelSeparator, configPanelSeparatorConstraints);

        JPanel targetPanel = buildTargetPanel();
        GridBagConstraints targetPanelConstraints = new GridBagConstraints();
        targetPanelConstraints.gridx = 0;
        targetPanelConstraints.gridy = yPosition++;
        targetPanelConstraints.ipadx = 5;
        targetPanelConstraints.ipady = 5;
        targetPanelConstraints.insets = optionsPanelInsets;
        targetPanelConstraints.weightx = 1.0;
        targetPanelConstraints.weighty = 1.0;
        targetPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        optionsPanel.add(targetPanel, targetPanelConstraints);

        loadOptionsProperties();

        return optionsPanel;
    }
    private JPanel buildHelpPanel()
    {

        JPanel helpPanel = new JPanel();
        JScrollPane helpScroll = new JScrollPane(helpPanel);
        JPanel helpBasePanel = new JPanel();
        helpBasePanel.setLayout(new GridBagLayout());
        Insets helpPanelInsets = new Insets(2, 0, 0, 0);
        helpPanel.setLayout(new GridBagLayout());
        int y = 0;

        JPanel generalHelpPanel = buildGeneralHelpPanel();
        GridBagConstraints generalHelpPanelConstraints = new GridBagConstraints();
        generalHelpPanelConstraints.gridx = 0;
        generalHelpPanelConstraints.gridy = y++;
        generalHelpPanelConstraints.ipadx = 5;
        generalHelpPanelConstraints.ipady = 5;
        generalHelpPanelConstraints.insets = helpPanelInsets;
        generalHelpPanelConstraints.weighty = 1;
        generalHelpPanelConstraints.weightx = 1;
        generalHelpPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        helpPanel.add(generalHelpPanel, generalHelpPanelConstraints);


        JSeparator generalHelpPanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        GridBagConstraints generalHelpPanelSeparatorConstraints = new GridBagConstraints();
        generalHelpPanelSeparatorConstraints.gridx = 0;
        generalHelpPanelSeparatorConstraints.gridy = y++;
        generalHelpPanelSeparatorConstraints.insets = helpPanelInsets;
        generalHelpPanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        generalHelpPanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        helpPanel.add(generalHelpPanelSeparator, generalHelpPanelSeparatorConstraints);

        JPanel differenceGeneratorPanel = buildDifferenceGeneratorPanel();
        GridBagConstraints differenceGeneratorConstraints = new GridBagConstraints();
        differenceGeneratorConstraints.gridx = 0;
        differenceGeneratorConstraints.gridy = y++;
        differenceGeneratorConstraints.ipadx = 5;
        differenceGeneratorConstraints.ipady = 5;
        differenceGeneratorConstraints.insets = helpPanelInsets;
        differenceGeneratorConstraints.weighty = 1;
        differenceGeneratorConstraints.weightx = 1;
        differenceGeneratorConstraints.anchor = GridBagConstraints.NORTHWEST;
        helpPanel.add(differenceGeneratorPanel, differenceGeneratorConstraints);

        JSeparator differenceGeneratorPanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        GridBagConstraints differenceGeneratorSeparatorConstraints = new GridBagConstraints();
        differenceGeneratorSeparatorConstraints.gridx = 0;
        differenceGeneratorSeparatorConstraints.gridy = y++;
        differenceGeneratorSeparatorConstraints.insets = helpPanelInsets;
        differenceGeneratorSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        differenceGeneratorSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        helpPanel.add(differenceGeneratorPanelSeparator, differenceGeneratorSeparatorConstraints);


        JPanel frameworkPanel = buildFrameworkPanel();
        GridBagConstraints frameworkPanelConstraints = new GridBagConstraints();
        frameworkPanelConstraints.gridx = 0;
        frameworkPanelConstraints.gridy = y++;
        frameworkPanelConstraints.ipadx = 5;
        frameworkPanelConstraints.ipady = 5;
        frameworkPanelConstraints.insets = helpPanelInsets;
        frameworkPanelConstraints.weighty = 1;
        frameworkPanelConstraints.weightx = 1;
        frameworkPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        helpPanel.add(frameworkPanel, frameworkPanelConstraints);

        JSeparator frameworkPanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        GridBagConstraints frameworkPanelSeparatorConstraints = new GridBagConstraints();
        frameworkPanelSeparatorConstraints.gridx = 0;
        frameworkPanelSeparatorConstraints.gridy = y++;
        frameworkPanelSeparatorConstraints.insets = helpPanelInsets;
        frameworkPanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        frameworkPanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        helpPanel.add(frameworkPanelSeparator, frameworkPanelSeparatorConstraints);

        JPanel fileFormatPanel = buildFileFormatPanel();
        GridBagConstraints fileFormatConstraints = new GridBagConstraints();
        fileFormatConstraints.gridx = 0;
        fileFormatConstraints.gridy = y++;
        fileFormatConstraints.ipadx = 5;
        fileFormatConstraints.ipady = 5;
        fileFormatConstraints.insets = helpPanelInsets;
        fileFormatConstraints.anchor = GridBagConstraints.NORTHWEST;
        helpPanel.add(fileFormatPanel, fileFormatConstraints);

        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.weightx = 1;
        gridBagConstraints.weighty = 1;
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        helpBasePanel.add(helpScroll, gridBagConstraints);

        return helpBasePanel;

    }

    private JPanel buildDifferenceGeneratorPanel()
    {
        JPanel differenceGeneratorPanel = new JPanel();
        differenceGeneratorPanel.setLayout(new GridBagLayout());
        int yPosition = 0;
        final JLabel differenceGeneratorPanelTitle = addPanelTitleToGridBagLayout("Attack Surface Difference Generator", differenceGeneratorPanel, yPosition++);
        final JLabel differenceGeneratorDescription = addPanelDescriptionToGridBagLayout("<html>The Attack Surface Difference Generator is a feature of the Attack Surface Detector plugin that is when importing from both source code or JSON.<br>" +
                " This feature is automatically enabled when two seperate versions of the same application are given on the configurations page and provides the following benefits:<html>" , differenceGeneratorPanel, yPosition++);

        final JLabel listLabel = addPanelDescriptionToGridBagLayout("<html><li> Compares two versions highlighting the differences between endpoints" +
                        " The results table will mark new or modified endpoints signifiny a change in the attack surface</li><br>" +
                        "<li>Viewing the details of a modified endpoint will show which parameters have been added, modified or deleted including data types and names</li><br>" +
                        "<li>Viewing the details of a new endpoint will display that the endpoint was not found in the previous version and show it's parameters if applicable</li></html>",
                differenceGeneratorPanel, yPosition++);

        return differenceGeneratorPanel;
    }

    private JPanel buildGeneralHelpPanel()
    {
        JPanel generalHelpPanel = new JPanel();
        generalHelpPanel.setLayout(new GridBagLayout());
        int yPosition = 0;
        final JLabel generalHelpPanelTitle = addPanelTitleToGridBagLayout("General Help", generalHelpPanel, yPosition++);
        final JLabel generalHelpPanelDescription = addPanelDescriptionToGridBagLayout("<html>The purpose of this section is to aid in general Attack Surface Detector usage. For any information or questions not addressed below please visit the following link:</html>", generalHelpPanel, yPosition++);
        String link = "<html><a href=\"https://github.com/secdec/attack-surface-detector-burp/wiki\" target=\"https://github.com/secdec/attack-surface-detector-burp/wiki\">https://github.com/secdec/attack-surface-detector-burp/wiki</a></html>";
        final JLabel linkLabel = addPanelDescriptionToGridBagLayout(link, generalHelpPanel, yPosition++);
        linkLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        linkLabel.addMouseListener(new MouseAdapter()
        {
            public void mouseClicked(MouseEvent e)
            {
                if (e.getClickCount() > 0)
                {
                    if (Desktop.isDesktopSupported())
                    {
                        Desktop desktop = Desktop.getDesktop();
                        try
                        {
                            URI uri = new URI("https://github.com/secdec/attack-surface-detector-burp/wiki");
                            desktop.browse(uri);
                        }
                        catch (IOException ex) { }
                        catch (URISyntaxException ex) { }
                    }
                    else { }
                }
            }
        });

        final JLabel importLabel = addPanelDescriptionToGridBagLayout("<html><li> Selecting \"Import Endpoints from Source\" or \"Import Endpoints from CLI JSON\" without" +
                        " configuring target and/or source/JSON location respectively <br>will show a configuration dialog prompting the user to do so</li><br>" +
                        "<li> To import endpoints in order to view their details without attacking the webapplication simply leave the target configuration empty and select submit on the pop up dialog</li><br>" +
                        "<li> To view the details of a specific endpoint simply click on an endpoint listed in the endpoints table of the main page</li><br></html>",
                generalHelpPanel, yPosition++);

        return generalHelpPanel;
    }

    private JPanel buildFrameworkPanel()
    {
        JPanel frameworkPanel = new JPanel();
        frameworkPanel.setLayout(new GridBagLayout());
        int yPosition = 0;
        final JLabel frameworkPanelTitle = addPanelTitleToGridBagLayout("Supported Frameworks", frameworkPanel, yPosition++);
        final JLabel frameworkPanelDescription = addPanelDescriptionToGridBagLayout("<html>The Attack Surface Detector uses static code analysis to identify web app endpoints by parsing routes and identifying parameters.<br> The following is a list of the supported languages and frameworks:</html>", frameworkPanel, yPosition++);
        final JLabel frameworksList = addPanelDescriptionToGridBagLayout("<html><li>C# / ASP.NET MVC </li><br>" +
                "<li>C# / Web Forms </li><br>" +
                "<li>Java / Spring MVC </li><br>" +
                "<li>Java / Struts </li><br>" +
                "<li>Java / JSP </li><br>" +
                "<li>Python / Django </li><br>" +
                "<li>Ruby / Rails <br></li></html>", frameworkPanel, yPosition++);

        return frameworkPanel;
    }

    private JPanel buildFileFormatPanel()
    {
        JPanel fileFormatPanel = new JPanel();
        fileFormatPanel.setLayout(new GridBagLayout());
        int yPosition = 0;
        final JLabel fileFormatPanelTitle = addPanelTitleToGridBagLayout("Accepted File Formats", fileFormatPanel, yPosition++);
        final JLabel sourcePanelDescription = addPanelDescriptionToGridBagLayout("<html>When importing endpoints from source code the accepted formats are as follows:</html>", fileFormatPanel, yPosition++);
        final JLabel zipFormatList = addPanelDescriptionToGridBagLayout("<html><li>Zip file | *.zip: A compresed version of a source code folder</li><br>" +
                "<li>War file | *.war: A .war file that contains compiled source code</li><br>"  +
                "<li>Directory | dir: A directory containing the source code of a supported framework</li><br></html>", fileFormatPanel, yPosition++);
        final JLabel jsonPanelDescription = addPanelDescriptionToGridBagLayout("<html>When importing endpoints from CLI JSON you must first have a serialized Attack Surface Detector-CLI JSON output file.  <br>To locate this tool and for general usage visit the Attack Surface Detector-CLI github page located below:</html>",fileFormatPanel, yPosition++);
        String link = "<html><a href=\"https://github.com/secdec/attack-surface-detector-cli\" target=\"https://github.com/secdec/attack-surface-detector-cli\">https://github.com/secdec/attack-surface-detector-cli</a></html>";
        final JLabel linkLabel = addPanelDescriptionToGridBagLayout(link, fileFormatPanel, yPosition++);
        linkLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        linkLabel.addMouseListener(new MouseAdapter()
        {
            public void mouseClicked(MouseEvent e)
            {
                if (e.getClickCount() > 0)
                {
                    if (Desktop.isDesktopSupported())
                    {
                        Desktop desktop = Desktop.getDesktop();
                        try
                        {
                            URI uri = new URI("https://github.com/secdec/attack-surface-detector-cli");
                            desktop.browse(uri);
                        }
                        catch (IOException ex) { }
                        catch (URISyntaxException ex) { }
                    }
                    else { }
                }
            }
        });

        return fileFormatPanel;
    }

    private JPanel buildDisplayPane()
    {
        final JLabel panelTitle = new JLabel("Selected Endpoint", JLabel.LEFT);
        panelTitle.setForeground(new Color(236, 136, 0));
        Font font = panelTitle.getFont();
        panelTitle.setFont(new Font(font.getFontName(), font.getStyle(), font.getSize() + 4));
        panelTitle.setHorizontalAlignment(SwingConstants.LEFT);
        JPanel basePanel = new JPanel();
        basePanel.setLayout(new BorderLayout());
        //displayArea.setText("\n" + "\n" + "\n" + "\n" + "\n" + "\n");
        callbacks.customizeUiComponent(displayArea);
        //displayArea.setEditable(false);
        JLabel titleLabel = new JLabel("Selected Endpoint");
        basePanel.add(panelTitle, BorderLayout.PAGE_START);
        JScrollPane scrollPane = new JScrollPane();
        JPanel displayPanel = new JPanel();
        displayPanel.setLayout(new BorderLayout());
        displayArea.setHorizontalAlignment(SwingConstants.LEFT);
        displayPanel.add(displayArea,BorderLayout.PAGE_START);
        JScrollPane scrollPane1 = new JScrollPane();
        scrollPane.setViewportView(displayPanel);
        //basePanel.add(new JScrollPane(displayArea), BorderLayout.CENTER);
        //basePanel.add(new JScrollPane(displayPanel), BorderLayout.CENTER);
        basePanel.add(scrollPane, BorderLayout.CENTER);
        return basePanel;
    }

    private JPanel buildEndpointsTable()
    {
        Object[][] data = {};
        String[] columnNames =
                {"Detected Endpoints",
                        "Number of Detected Parameters",
                        "GET Method",
                        "POST Method",
                        "New/Modified",
                        "Endpoint"
                };

        DefaultTableModel dtm = new DefaultTableModel(data, columnNames){

            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };

        JTable endpointsTable = new JTable(dtm);
        endpointsTable.addMouseListener(new MouseListener()
        {
            @Override
            public void mouseClicked(MouseEvent e)
            {
                String displayStr = new String();
                displayArea.setText(displayStr);
                EndpointDecorator decorator = (EndpointDecorator)endpointsTable.getModel().getValueAt(endpointsTable.getSelectedRow(), 5);
                Endpoint.Info endpoint = decorator.getEndpoint();
                if(decorator.getStatus() == EndpointDecorator.Status.NEW)
                {
                    displayStr = "<html><b>New Endpoint</b><br>";
                    displayStr = displayStr + "URL:<br>";
                }
                else
                    displayStr = displayStr + "<html> URL:<br>";

                displayStr = displayStr + "" + endpoint.getUrlPath() + "<br><br>Methods:<br>";
                // TODO - Gather all Endpoint objects pointing to the same endpoint and output their HTTP methods (Endpoints only have
                //  one HTTP method at a time now)
                if(endpoint.getHttpMethod().length() >4)
                    displayStr = displayStr + endpoint.getHttpMethod().substring(14);
                else
                    displayStr = displayStr + endpoint.getHttpMethod();


                displayStr = displayStr +"<br>Parameters and type:<br>";
                if(decorator.getStatus() == EndpointDecorator.Status.CHANGED)
                {
                    for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
                    {   boolean found = false;
                        for (Map.Entry<String, RouteParameter> compParameter : decorator.getComparePoint().getParameters().entrySet())
                        {
                            if (parameter.getKey().equalsIgnoreCase(compParameter.getKey()))
                            {
                                found = true;
                                if(!parameter.getValue().getDataType().getDisplayName().equals(compParameter.getValue().getDataType().getDisplayName()))
                                    displayStr = displayStr + "<strong>" + parameter.getKey() + " - " + compParameter.getValue().getDataType().getDisplayName().toUpperCase() + " -> " + parameter.getValue().getDataType().getDisplayName().toUpperCase()+"</strong> (modified parameter type) <br>";
                                else
                                    displayStr = displayStr + parameter.getKey() + " - "+ parameter.getValue().getDataType().getDisplayName() + "<br>";
                                break;
                            }
                        }
                        if (!found)
                            displayStr = displayStr + "<strong>" + parameter.getKey() + "</strong> - <strong>" + parameter.getValue().getDataType().getDisplayName().toUpperCase() + "</strong> (added parameter)<br>";
                    }
                    for (Map.Entry<String, RouteParameter> compParameter : decorator.getComparePoint().getParameters().entrySet())
                    {   boolean found = false;
                        for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
                        {
                            if (parameter.getKey().equalsIgnoreCase(compParameter.getKey()))
                            {
                                found = true;
                                break;
                            }
                        }
                        if(!found)
                            displayStr = displayStr + "<span style='text-decoration: line-through;'>" +compParameter.getKey() + " - " + compParameter.getValue().getDataType().getDisplayName().toUpperCase() + "</span> (removed parameter)<br>";
                    }
                }
                else
                {
                    for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
                    {
                        displayStr = displayStr + parameter.getKey() + " - "+ parameter.getValue().getDataType().getDisplayName() + "<br>";
                    }
                }

                displayStr = displayStr + "</html>";
                displayArea.setText(displayStr);

            }
            @Override
            public void mousePressed(MouseEvent e) { }
            @Override
            public void mouseReleased(MouseEvent e) { }
            @Override
            public void mouseEntered(MouseEvent e) { }
            @Override
            public void mouseExited(MouseEvent e) { }
        });

        TableColumn tc = endpointsTable.getColumnModel().getColumn(2);
        tc.setCellEditor(endpointsTable.getDefaultEditor(Boolean.class));
        tc.setCellRenderer(endpointsTable.getDefaultRenderer(Boolean.class));
        tc = endpointsTable.getColumnModel().getColumn(3);
        tc.setCellEditor(endpointsTable.getDefaultEditor(Boolean.class));
        tc.setCellRenderer(endpointsTable.getDefaultRenderer(Boolean.class));
        tc = endpointsTable.getColumnModel().getColumn(4);
        tc.setCellEditor(endpointsTable.getDefaultEditor(Boolean.class));
        tc.setCellRenderer(endpointsTable.getDefaultRenderer(Boolean.class));
        endpointsTable.getColumnModel().getColumn(5).setMinWidth(0);
        endpointsTable.getColumnModel().getColumn(5).setMaxWidth(0);
        endpointsTable.getColumnModel().getColumn(5).setWidth(0);
        JScrollPane endpointsTablePane = new JScrollPane(endpointsTable);

        endpointsTable.setFillsViewportHeight(true);
        callbacks.customizeUiComponent(endpointsTable);
        BurpPropertiesManager.getBurpPropertiesManager().setEndpointsTable(endpointsTable);

        JPanel basePanel = new JPanel();
        basePanel.setLayout(new BorderLayout());
        JLabel countLabel = new JLabel();
        callbacks.customizeUiComponent(countLabel);
        BurpPropertiesManager.getBurpPropertiesManager().setCountLabel(countLabel);
        countLabel.setBorder(null);
        countLabel.setText(" ");
        basePanel.add(countLabel, BorderLayout.PAGE_START);
        basePanel.add(endpointsTablePane, BorderLayout.CENTER);

        return basePanel;

    }


    private JPanel buildImportExportPanel()
    {
        JPanel importExportPanel = new JPanel();
        importExportPanel.setLayout(new GridBagLayout());
        int yPosition = 0;

        addPanelTitleToGridBagLayout("Source Code Analysis", importExportPanel, yPosition++);
        addPanelDescriptionToGridBagLayout("Use Attack Surface Detector to analyze the server side source code to detect endpoints and parameters and import them into Burp." , importExportPanel, yPosition++);
        addPanelDescriptionToGridBagLayout("These results may include URL endpoints and optional parameters a spider may not find." , importExportPanel, yPosition++);

        JButton localEndpointsButton = new LocalEndpointsButton(getUiComponent(), callbacks);
        callbacks.customizeUiComponent(localEndpointsButton);

        localEndpointsButton.setSize(300, 30);
        localEndpointsButton.setLocation(10,400);

        GridBagConstraints gridBagConstraintsLocal = new GridBagConstraints();
        gridBagConstraintsLocal.gridwidth = 1;
        gridBagConstraintsLocal.gridx = 1;
        gridBagConstraintsLocal.gridy = ++yPosition;
        gridBagConstraintsLocal.ipadx = 5;
        gridBagConstraintsLocal.ipady = 5;
        gridBagConstraintsLocal.anchor = GridBagConstraints.NORTHWEST;

        importExportPanel.add(localEndpointsButton, gridBagConstraintsLocal);

        JButton serializedEndpointsButton = new SerializedEndpointsButton(getUiComponent(), callbacks);
        callbacks.customizeUiComponent(localEndpointsButton);

        serializedEndpointsButton.setSize(300, 30);
        serializedEndpointsButton.setLocation(10,400);

        gridBagConstraintsLocal = new GridBagConstraints();
        gridBagConstraintsLocal.gridwidth = 1;
        gridBagConstraintsLocal.gridx = 2;
        gridBagConstraintsLocal.gridy = yPosition++;
        gridBagConstraintsLocal.ipadx = 5;
        gridBagConstraintsLocal.ipady = 5;
        gridBagConstraintsLocal.anchor = GridBagConstraints.NORTHWEST;

        importExportPanel.add(serializedEndpointsButton, gridBagConstraintsLocal);

        return importExportPanel;
    }


    private JPanel buildSourcePanel() {
        final JPanel sourcePanel = new JPanel();
        sourcePanel.setLayout(new GridBagLayout());
        int yPosition = 0;
        JPanel titlePanel = new JPanel();
        titlePanel.setLayout(new GridBagLayout());

        final JLabel sourcePanelTitle = addPanelTitleToGridBagLayout("Local Source Code", sourcePanel, yPosition++);
        final JLabel sourcePanelDescription = addPanelDescriptionToGridBagLayout("<html>This setting lets you configure the location of your source code.<br>For more information on supported frameworks and general usage click the link below:", sourcePanel, yPosition++);
        String link = "<html><a href=\"https://github.com/secdec/attack-surface-detector-burp/wiki\" target=\"https://github.com/secdec/attack-surface-detector-burp/wiki\">https://github.com/secdec/attack-surface-detector-burp/wiki</a></html>";
        final JLabel linkLabel = addPanelDescriptionToGridBagLayout(link, sourcePanel, yPosition++);
        final JLabel differenceGeneratorDescription = addPanelDescriptionToGridBagLayout("<html><br>You can optionally choose to compare two different versions of the source code, and the Attack Surface Detector <br>will highlight endpoints and parameters that are new or modified in the newer version of the source code.</html>", sourcePanel, yPosition++);
        final JLabel sourcePanelDescription2 = addPanelDescriptionToGridBagLayout(" ", sourcePanel, yPosition++);
        linkLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        linkLabel.addMouseListener(new MouseAdapter() {

            public void mouseClicked(MouseEvent e) {

                if (e.getClickCount() > 0) {

                    if (Desktop.isDesktopSupported()) {

                        Desktop desktop = Desktop.getDesktop();

                        try {

                            URI uri = new URI("https://github.com/secdec/attack-surface-detector-burp/wiki");

                            desktop.browse(uri);

                        } catch (IOException ex) { }
                        catch (URISyntaxException ex) { }
                    } else { }
                }

            }

        });
        final JButton sourceFolderBrowseButton = new JButton("Select folder or zip file ...");
        sourceFolderBrowseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                JFileChooser chooser = new JFileChooser();
                String currentDirectory = sourceFolderField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                    currentDirectory = System.getProperty("user.home");
                }
                chooser.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser.setDialogTitle("Please select the folder containing the source code");
                chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
                chooser.setAcceptAllFileFilterUsed(false);
                chooser.addChoosableFileFilter( new FileNameExtensionFilter("*.zip | ZIP archive", "zip"));
                chooser.addChoosableFileFilter( new FileNameExtensionFilter("*.war | Web application archive", "war"));
                chooser.addChoosableFileFilter( new FileFilter()
                {
                    public boolean accept(File f)
                    {
                        return f.isDirectory();
                    }

                    public String getDescription()
                    {
                        return "dir | Directory/Folder";
                    }
                });
                if (chooser.showOpenDialog(sourcePanel) == JFileChooser.APPROVE_OPTION) {
                    sourceFolderField.setText(chooser.getSelectedFile().getAbsolutePath());
                    BurpPropertiesManager.getBurpPropertiesManager().setSourceFolder(sourceFolderField.getText());
                }
            }
        });
        sourceFolderField = addTextFieldToGridBagLayout("Source code to analyze:", sourcePanel, yPosition++, BurpPropertiesManager.SOURCE_FOLDER_KEY, sourceFolderBrowseButton);

        final JButton oldSourceFolderBrowseButton = new JButton("Select folder or zip file ...");
        oldSourceFolderBrowseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                JFileChooser chooser2 = new JFileChooser();
                String currentDirectory = oldSourceFolderField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                    currentDirectory = System.getProperty("user.home");
                }
                chooser2.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser2.setDialogTitle("Please select the folder containing the source code");
                chooser2.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
                chooser2.setAcceptAllFileFilterUsed(false);
                chooser2.addChoosableFileFilter( new FileNameExtensionFilter("*.zip | ZIP archive", "zip"));
                chooser2.addChoosableFileFilter( new FileNameExtensionFilter("*.war | Web application archive", "war"));
                chooser2.addChoosableFileFilter( new FileFilter()
                {
                    public boolean accept(File f)
                    {
                        return f.isDirectory();
                    }

                    public String getDescription()
                    {
                        return "dir | Directory/Folder";
                    }
                });
                if (chooser2.showOpenDialog(sourcePanel) == JFileChooser.APPROVE_OPTION) {
                    oldSourceFolderField.setText(chooser2.getSelectedFile().getAbsolutePath());
                    BurpPropertiesManager.getBurpPropertiesManager().setOldSourceFolder(oldSourceFolderField.getText());
                }
            }
        });


        oldSourceFolderField = addTextFieldToGridBagLayout("Comparison source code (optional):", sourcePanel, yPosition++, BurpPropertiesManager.OLD_SOURCE_FOLDER_KEY, oldSourceFolderBrowseButton);

        return sourcePanel;
    }

    private JPanel buildSerializationPanel() {
        final JPanel serializationPanel = new JPanel();
        serializationPanel.setLayout(new GridBagLayout());
        int yPosition = 0;
        JPanel titlePanel = new JPanel();
        titlePanel.setLayout(new GridBagLayout());
        String link = "<html><a href=\"https://github.com/secdec/attack-surface-detector-cli\" target=\"https://github.com/secdec/attack-surface-detector-cli\">https://github.com/secdec/attack-surface-detector-cli</a></html>";

        final JLabel serializationPanelTitle = addPanelTitleToGridBagLayout("Attack Surface Detector CLI JSON", serializationPanel, yPosition++);
        final JLabel serializationPanelDescription = addPanelDescriptionToGridBagLayout("<html>The CLI tool is a command line interface version of Attack Surface Detector that can produce a serialized JSON output of a supported web applications endpoints. <br>To find this tool or help using it please visit the link below:</html>", serializationPanel, yPosition++);
        final JLabel linkLabel = addPanelDescriptionToGridBagLayout(link, serializationPanel, yPosition++);
        final JLabel differenceGeneratorDescription = addPanelDescriptionToGridBagLayout("<html><br>You can optionally choose to compare two different versions of the endpoint JSON files, and the Attack Surface Detector <br>will highlight endpoints and parameters that are new or modified in the newer version of the application.</html>", serializationPanel, yPosition++);
        final JLabel serializationPanelDescription2 = addPanelDescriptionToGridBagLayout(" ", serializationPanel, yPosition++);
        linkLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        linkLabel.addMouseListener(new MouseAdapter() {

            public void mouseClicked(MouseEvent e) {

                if (e.getClickCount() > 0) {

                    if (Desktop.isDesktopSupported()) {

                        Desktop desktop = Desktop.getDesktop();

                        try {

                            URI uri = new URI("https://github.com/secdec/attack-surface-detector-cli");

                            desktop.browse(uri);

                        } catch (IOException ex) { }
                        catch (URISyntaxException ex) { }
                    } else { }
                }

            }

        });
        final JButton sourceFolderBrowseButton = new JButton("Select JSON file ...");
        sourceFolderBrowseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                JFileChooser chooser = new JFileChooser();
                String currentDirectory = serializationField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                    currentDirectory = System.getProperty("user.home");
                }
                chooser.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser.setDialogTitle("Please select endpoint JSON file");
                chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                chooser.setAcceptAllFileFilterUsed(false);
                chooser.addChoosableFileFilter( new FileNameExtensionFilter("*.json | JSON File", "json"));
                if (chooser.showOpenDialog(serializationPanel) == JFileChooser.APPROVE_OPTION) {
                    serializationField.setText(chooser.getSelectedFile().getAbsolutePath());
                    BurpPropertiesManager.getBurpPropertiesManager().setSerializationFile(serializationField.getText());
                }
            }
        });
        serializationField = addTextFieldToGridBagLayout("Endpoint JSON to analyze:", serializationPanel, yPosition++, BurpPropertiesManager.SERIALIZATION_KEY, sourceFolderBrowseButton);

        final JButton oldSourceFolderBrowseButton = new JButton("Select JSON file ...");
        oldSourceFolderBrowseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                JFileChooser chooser2 = new JFileChooser();
                String currentDirectory = oldSerializationField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                    currentDirectory = System.getProperty("user.home");
                }
                chooser2.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser2.setDialogTitle("Please select endpoint JSON file");
                chooser2.setFileSelectionMode(JFileChooser.FILES_ONLY);
                chooser2.setAcceptAllFileFilterUsed(false);
                chooser2.addChoosableFileFilter( new FileNameExtensionFilter("*.json | JSON File", "json"));
                if (chooser2.showOpenDialog(serializationPanel) == JFileChooser.APPROVE_OPTION) {
                    oldSerializationField.setText(chooser2.getSelectedFile().getAbsolutePath());
                    BurpPropertiesManager.getBurpPropertiesManager().setOldSerializationFile(oldSerializationField.getText());
                }
            }
        });


        oldSerializationField = addTextFieldToGridBagLayout("Comparison endpoint JSON (optional):", serializationPanel, yPosition++, BurpPropertiesManager.OLD_SERIALIZATION_KEY, oldSourceFolderBrowseButton);

        return serializationPanel;
    }

    private JPanel buildConfigPanel() {
        final JPanel configPanel = new JPanel();
        configPanel.setLayout(new GridBagLayout());
        int yPosition = 0;

        final JLabel configPanelTitle = addPanelTitleToGridBagLayout("Burp Configuration File", configPanel, yPosition++);
        final JLabel configPanelDescription = addPanelDescriptionToGridBagLayout("This setting lets you configure the location of your Burp configuration file.", configPanel, yPosition++);

        final JButton configFileBrowseButton = new JButton("Select file ...");
        configFileBrowseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                JFileChooser chooser = new JFileChooser();
                String currentDirectory = configFileField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                    currentDirectory = System.getProperty("user.home");
                }
                chooser.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser.setDialogTitle("Please select the burp configuration file");
                chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
                chooser.setAcceptAllFileFilterUsed(false);
                if (chooser.showOpenDialog(configPanel) == JFileChooser.APPROVE_OPTION) {
                    configFileField.setText(chooser.getSelectedFile().getAbsolutePath());
                    BurpPropertiesManager.getBurpPropertiesManager().setConfigFile(configFileField.getText());
                }
            }
        });
        configFileField = addTextFieldToGridBagLayout("Location of configuration file:", configPanel, yPosition++, BurpPropertiesManager.CONFIG_FILE_KEY, configFileBrowseButton);

        return configPanel;
    }

    private JPanel buildTargetPanel() {
        final JPanel targetPanel = new JPanel();
        targetPanel.setLayout(new GridBagLayout());
        int yPosition = 0;

        ActionListener applicationCheckBoxHttpActionListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                BurpPropertiesManager.getBurpPropertiesManager().setUseHttps(useHttpField.isSelected());
            }
        };

        final JLabel targetPanelTitle = addPanelTitleToGridBagLayout("Target Configuration", targetPanel, yPosition++);
        targetHostField = addTextFieldToGridBagLayout("Host:", targetPanel, yPosition++, BurpPropertiesManager.TARGET_HOST_KEY);
        targetPortField = addTextFieldToGridBagLayout("Port:", targetPanel, yPosition++, BurpPropertiesManager.TARGET_PORT_KEY);
        targetPathField = addTextFieldToGridBagLayout("Path (optional):", targetPanel, yPosition++, BurpPropertiesManager.TARGET_PATH_KEY);
        useHttpField = addCheckBoxToGridBagLayout("Use HTTPS", targetPanel, yPosition++, applicationCheckBoxHttpActionListener);
        useHttpField.setSelected(BurpPropertiesManager.getBurpPropertiesManager().getUseHttps());
        //BurpPropertiesManager.getBurpPropertiesManager().setUseHttpsField(useHttpField);
        PlainDocument portDoc = (PlainDocument)targetPortField.getDocument();
        portDoc.setDocumentFilter(new PortFilter());
        return targetPanel;
    }

    private JPanel buildAutoOptionsPanel() {
        final JPanel autoOptionsPanel = new JPanel();
        autoOptionsPanel.setLayout(new GridBagLayout());
        int yPosition = 0;

        final JLabel autoOptionsPanelTitle = addPanelTitleToGridBagLayout("Attack Surface Detector Plugin Behavior", autoOptionsPanel, yPosition++);
        ActionListener applicationCheckBoxSpiderActionListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                BurpPropertiesManager.getBurpPropertiesManager().setAutoSpider(autoSpiderField.isSelected());
                if(BurpPropertiesManager.getBurpPropertiesManager().getAutoSpider() && BurpPropertiesManager.getBurpPropertiesManager().isProVersion())
                {
                    autoScanField.setEnabled(true);
                    autoScanText.setForeground(Color.BLACK);
                }
                else
                {
                    autoScanField.setEnabled(false);
                    BurpPropertiesManager.getBurpPropertiesManager().setAutoScan(false);
                    autoScanField.setSelected(false);
                    autoScanText.setForeground(Color.GRAY);
                }
            }
        };

        ActionListener applicationCheckBoxScanActionListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                BurpPropertiesManager.getBurpPropertiesManager().setAutoScan(autoScanField.isSelected());
            }
        };
        autoScanText = new JLabel("Automatically start active scanner after automatic spider: ");
        autoSpiderField = addCheckBoxToGridBagLayout(new JLabel("Automatically start spider after importing endpoints: "), autoOptionsPanel, yPosition++, applicationCheckBoxSpiderActionListener);
        if(BurpPropertiesManager.getBurpPropertiesManager().isProVersion())
        {
            autoScanField = addCheckBoxToGridBagLayout(autoScanText, autoOptionsPanel, yPosition++, applicationCheckBoxScanActionListener);
            if (BurpPropertiesManager.getBurpPropertiesManager().getAutoSpider())
            {
                autoScanField.setEnabled(true);
                autoScanText.setForeground(Color.BLACK);
            }
            else
            {
                autoScanText.setForeground(Color.GRAY);
                autoScanField.setEnabled(false);
            }
        }
        else
        {
            autoScanField = addCheckBoxToGridBagLayout(autoScanText, autoOptionsPanel, yPosition++, applicationCheckBoxScanActionListener);
            autoScanField.setEnabled(false);
            profMessage = addPanelLabelToGridBagLayout("\t *Note this option is only available with the Pro Version", autoOptionsPanel, yPosition++);
        }

        return autoOptionsPanel;
    }


    @Override
    public String getTabCaption()
    {
        return "Attack Surface Detector";
    }

    @Override
    public Component getUiComponent()
    {
        return tabbedPane;
    }

    private class ThreadFixPropertyFieldListener implements DocumentListener, FocusListener {
        private JTextField jTextField;
        private String propertyName;
        private Runnable runnable;

        private String lastValue = null;

        public ThreadFixPropertyFieldListener(JTextField jTextField, String propertyName) {
            this(jTextField, propertyName, null);
        }

        public ThreadFixPropertyFieldListener(JTextField jTextField, String propertyName, Runnable runnable) {
            this.jTextField = jTextField;
            this.propertyName = propertyName;
            this.runnable = runnable;
        }

        protected void update() {
            BurpPropertiesManager.getBurpPropertiesManager().setPropertyValue(propertyName, jTextField.getText().trim());
            if (runnable != null) {
                runnable.run();
            }
        }

        @Override
        public void insertUpdate(DocumentEvent e) {
            update();
        }

        @Override
        public void removeUpdate(DocumentEvent e) {
            update();
        }

        @Override
        public void changedUpdate(DocumentEvent e) {
            update();
        }

        @Override
        public void focusGained(FocusEvent e) {
            lastValue = jTextField.getText().trim();
        }

        @Override
        public void focusLost(FocusEvent e) {
            String currentValue = jTextField.getText().trim();
            if (!currentValue.equals(lastValue)) {
                update();
            }
        }
    }

    private void loadOptionsProperties() {
        BurpPropertiesManager burpPropertiesManager = BurpPropertiesManager.getBurpPropertiesManager();
        sourceFolderField.setText(burpPropertiesManager.getSourceFolder());
        oldSourceFolderField.setText(burpPropertiesManager.getOldSourceFolder());
        serializationField.setText(burpPropertiesManager.getSerializationFile());
        oldSerializationField.setText(burpPropertiesManager.getOldSerializationFile());
        configFileField.setText(burpPropertiesManager.getConfigFile());
        targetHostField.setText(burpPropertiesManager.getTargetHost());
        targetPathField.setText(burpPropertiesManager.getTargetPath());
        targetPortField.setText(burpPropertiesManager.getTargetPort());
    }


    private JLabel addPanelTitleToGridBagLayout(String titleText, Container gridBagContainer, int yPosition) {
        final JLabel panelTitle = new JLabel(titleText, JLabel.LEFT);
        panelTitle.setForeground(new Color(236, 136, 0));
        Font font = panelTitle.getFont();
        panelTitle.setFont(new Font(font.getFontName(), font.getStyle(), font.getSize() + 4));
        panelTitle.setHorizontalAlignment(SwingConstants.LEFT);
        callbacks.customizeUiComponent(panelTitle);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.NORTH;
        gridBagContainer.add(panelTitle, gridBagConstraints);
        return panelTitle;
    }

    private JLabel addPanelLabelToGridBagLayout(String titleText, Container gridBagContainer, int yPosition) {
        final JLabel panelTitle = new JLabel(titleText);
        panelTitle.setForeground(new Color(236, 136, 0));
        Font font = panelTitle.getFont();
        panelTitle.setFont(new Font(font.getFontName(), font.getStyle(), font.getSize()));
        panelTitle.setHorizontalAlignment(SwingConstants.LEFT);
        callbacks.customizeUiComponent(panelTitle);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.NORTH;
        gridBagContainer.add(panelTitle, gridBagConstraints);
        return panelTitle;
    }

    private JLabel addPanelDescriptionToGridBagLayout(String descriptionText, Container gridBagContainer, int yPosition) {
        final JLabel panelDescription = new JLabel(descriptionText);
        panelDescription.setHorizontalAlignment(SwingConstants.LEFT);
        callbacks.customizeUiComponent(panelDescription);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagContainer.add(panelDescription, gridBagConstraints);
        return panelDescription;
    }

    private JLabel addErrorMessageToGridBagLayout(Container gridBagContainer, int yPosition) {
        final JLabel errorMessage = new JLabel("");
        errorMessage.setForeground(new Color(255, 0, 0));
        errorMessage.setHorizontalAlignment(SwingConstants.LEFT);
        callbacks.customizeUiComponent(errorMessage);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 10;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagContainer.add(errorMessage, gridBagConstraints);
        return errorMessage;
    }

    private JTextField addTextFieldToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, String propertyKey) {
        return addTextFieldToGridBagLayout(labelText, gridBagContainer, yPosition, propertyKey, null, null);
    }

    private JTextField addTextFieldToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, String propertyKey, Runnable threadFixPropertyFieldListenerRunnable) {
        return addTextFieldToGridBagLayout(labelText, gridBagContainer, yPosition, propertyKey, threadFixPropertyFieldListenerRunnable, null);
    }

    private JTextField addTextFieldToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, String propertyKey, JButton button) {
        return addTextFieldToGridBagLayout(labelText, gridBagContainer, yPosition, propertyKey, null, button);
    }

    private JTextField addTextFieldToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, String propertyKey, Runnable threadFixPropertyFieldListenerRunnable, JButton button) {
        JLabel textFieldLabel = new JLabel(labelText);
        callbacks.customizeUiComponent(textFieldLabel);
        textFieldLabel.setHorizontalAlignment(SwingConstants.LEFT);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 1;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagContainer.add(textFieldLabel, gridBagConstraints);

        JTextField textField = new JTextField(40);
        callbacks.customizeUiComponent(textField);
        textField.addFocusListener(new ThreadFixPropertyFieldListener(textField, propertyKey, threadFixPropertyFieldListenerRunnable));
        gridBagConstraints = new GridBagConstraints();
        if (button == null) {
            gridBagConstraints.gridwidth = 2;
        } else {
            gridBagConstraints.gridwidth = 1;
        }
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagContainer.add(textField, gridBagConstraints);

        if (button != null) {
            callbacks.customizeUiComponent(button);
            gridBagConstraints = new GridBagConstraints();
            gridBagConstraints.gridwidth = 1;
            gridBagConstraints.gridx = 3;
            gridBagConstraints.gridy = yPosition;
            //gridBagConstraints.ipadx = 5;
            //gridBagConstraints.ipady = 5;
            gridBagConstraints.fill = GridBagConstraints.NONE;
            gridBagConstraints.anchor = GridBagConstraints.WEST;
            gridBagContainer.add(button, gridBagConstraints);
        }

        return textField;
    }


    private JComboBox addComboBoxToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, ActionListener actionListener) {
        return addComboBoxToGridBagLayout(labelText, gridBagContainer, yPosition, actionListener, null);
    }

    private JComboBox addComboBoxToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, ActionListener actionListener, JButton button) {
        JLabel textFieldLabel = new JLabel(labelText);
        callbacks.customizeUiComponent(textFieldLabel);
        textFieldLabel.setHorizontalAlignment(SwingConstants.LEFT);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 1;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagContainer.add(textFieldLabel, gridBagConstraints);

        JComboBox comboBox = new JComboBox();
        comboBox.setEnabled(false);
        callbacks.customizeUiComponent(comboBox);
        gridBagConstraints = new GridBagConstraints();
        if (button == null) {
            gridBagConstraints.gridwidth = 2;
        } else {
            gridBagConstraints.gridwidth = 1;
        }
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.NORTH;
        gridBagContainer.add(comboBox, gridBagConstraints);

        if (button != null) {
            callbacks.customizeUiComponent(button);
            gridBagConstraints = new GridBagConstraints();
            gridBagConstraints.gridwidth = 1;
            gridBagConstraints.gridx = 3;
            gridBagConstraints.gridy = yPosition;
            gridBagConstraints.ipadx = 5;
            gridBagConstraints.ipady = 5;
            gridBagConstraints.fill = GridBagConstraints.NONE;
            gridBagConstraints.anchor = GridBagConstraints.NORTHEAST;
            gridBagContainer.add(button, gridBagConstraints);
        }

        comboBox.addActionListener(actionListener);

        return comboBox;
    }

    private JCheckBox addCheckBoxToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, ActionListener actionListener) {
        return addCheckBoxToGridBagLayout(labelText, gridBagContainer, yPosition, actionListener, null);
    }

    private JCheckBox addCheckBoxToGridBagLayout(JLabel label, Container gridBagContainer, int yPosition, ActionListener actionListener) {
        return addCheckBoxToGridBagLayout(label, gridBagContainer, yPosition, actionListener, null);
    }

    private JCheckBox addCheckBoxToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, ActionListener actionListener, JButton button) {
        JLabel textFieldLabel = new JLabel(labelText);
        callbacks.customizeUiComponent(textFieldLabel);
        JCheckBox checkBox = new JCheckBox();
        callbacks.customizeUiComponent(checkBox);

        textFieldLabel.setHorizontalAlignment(SwingConstants.LEFT);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        //gridBagConstraints.ipadx = 5;
        //gridBagConstraints.ipady = 5;
        //gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagConstraints.insets = new Insets(0,22,0,0);
        gridBagContainer.add(textFieldLabel, gridBagConstraints);

        gridBagConstraints = new GridBagConstraints();
        if (button == null) {
            gridBagConstraints.gridwidth = 2;
        } else {
            gridBagConstraints.gridwidth = 1;
        }
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        //gridBagConstraints.ipadx = 5;
        //gridBagConstraints.ipady = 5;
        //gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagContainer.add(checkBox, gridBagConstraints);

        if (button != null) {
            callbacks.customizeUiComponent(button);
            gridBagConstraints = new GridBagConstraints();
            gridBagConstraints.gridwidth = 1;
            gridBagConstraints.gridx = 3;
            gridBagConstraints.gridy = yPosition;
            gridBagConstraints.ipadx = 5;
            gridBagConstraints.ipady = 5;
            gridBagConstraints.fill = GridBagConstraints.NONE;
            gridBagConstraints.anchor = GridBagConstraints.NORTHEAST;
            gridBagContainer.add(button, gridBagConstraints);
        }

        checkBox.addActionListener(actionListener);

        return checkBox;
    }

    private JCheckBox addCheckBoxToGridBagLayout(JLabel textFieldLabel, Container gridBagContainer, int yPosition, ActionListener actionListener, JButton button) {
        callbacks.customizeUiComponent(textFieldLabel);
        JCheckBox checkBox = new JCheckBox();
        callbacks.customizeUiComponent(checkBox);

        textFieldLabel.setHorizontalAlignment(SwingConstants.LEFT);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 1;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        //gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagContainer.add(checkBox, gridBagConstraints);


        gridBagConstraints = new GridBagConstraints();
        if (button == null) {
            gridBagConstraints.gridwidth = 2;
        } else {
            gridBagConstraints.gridwidth = 1;
        }
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        //gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagContainer.add(textFieldLabel, gridBagConstraints);

        if (button != null) {
            callbacks.customizeUiComponent(button);
            gridBagConstraints = new GridBagConstraints();
            gridBagConstraints.gridwidth = 1;
            gridBagConstraints.gridx = 3;
            gridBagConstraints.gridy = yPosition;
            gridBagConstraints.ipadx = 5;
            gridBagConstraints.ipady = 5;
            gridBagConstraints.fill = GridBagConstraints.NONE;
            gridBagConstraints.anchor = GridBagConstraints.NORTHEAST;
            gridBagContainer.add(button, gridBagConstraints);
        }

        checkBox.addActionListener(actionListener);

        return checkBox;
    }
}

class PortFilter extends DocumentFilter {
    static final int maxLength = 5;
    @Override
    public void insertString(FilterBypass fb, int offset, String string,
                             AttributeSet attr) throws BadLocationException {
        Document doc = fb.getDocument();
        StringBuilder sb = new StringBuilder();
        sb.append(doc.getText(0, doc.getLength()));
        sb.insert(offset, string);
        int val = Integer.parseInt(sb.toString());

        if (isInteger(sb.toString()) && sb.length() <= maxLength && val <= 65535) {
            super.insertString(fb, offset, string, attr);
        } else {
            Toolkit.getDefaultToolkit().beep();
        }
    }

    private boolean isInteger(String text) {
        try {
            Integer.parseInt(text);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    @Override
    public void replace(FilterBypass fb, int offset, int length, String text,
                        AttributeSet attrs) throws BadLocationException {

        Document doc = fb.getDocument();
        StringBuilder sb = new StringBuilder();
        sb.append(doc.getText(0, doc.getLength()));
        sb.replace(offset, offset + length, text);
        int val = Integer.parseInt(sb.toString());

        if (isInteger(sb.toString()) && (sb.length() <= maxLength) && val <= 65535) {
            super.replace(fb, offset, length, text, attrs);
        } else {
            Toolkit.getDefaultToolkit().beep();
        }

    }

    @Override
    public void remove(FilterBypass fb, int offset, int length)
            throws BadLocationException {
        Document doc = fb.getDocument();
        StringBuilder sb = new StringBuilder();
        sb.append(doc.getText(0, doc.getLength()));
        sb.delete(offset, offset + length);

        if ((isInteger(sb.toString()) && (sb.length() <= maxLength)) || (sb.length() == 0)) {
            super.remove(fb, offset, length);
        } else {
            Toolkit.getDefaultToolkit().beep();
        }

    }
}