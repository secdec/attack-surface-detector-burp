////////////////////////////////////////////////////////////////////////
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
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package burp.dialog;

import burp.IBurpExtenderCallbacks;
import burp.extention.BurpPropertiesManager;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.File;

public class ConfigurationDialogs
{
    public static enum DialogMode {SOURCE;}
	public ConfigurationDialogs() {}
	
	public static boolean show(Component view, DialogMode mode)
    {
            boolean shouldContinue = (!BurpPropertiesManager.getBurpPropertiesManager().getSourceFolder().trim().isEmpty());
            if(!shouldContinue)
            {
                JPanel sourcePanel = new JPanel();
                JLabel sourcePanelLabel = new JLabel("Source code to analyze: ");
                final JButton sourceFolderBrowseButton = new JButton("Select folder or zip file...");
                JTextField sourceFolderField = new JTextField(30);
                IBurpExtenderCallbacks callbacks =  BurpPropertiesManager.getBurpPropertiesManager().getCallbacks();
                callbacks.customizeUiComponent(sourceFolderField);
                sourceFolderBrowseButton.addActionListener(new ActionListener()
                {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e)
                    {
                        JFileChooser chooser = new JFileChooser();
                        String currentDirectory = sourceFolderField.getText();
                        if ((currentDirectory == null) || (currentDirectory.trim().equals("")))
                            currentDirectory = System.getProperty("user.home");

                        chooser.setCurrentDirectory(new java.io.File(currentDirectory));
                        chooser.setDialogTitle("Please select the folder or zip file containing the source code");
                        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
                        chooser.setAcceptAllFileFilterUsed(false);
                        chooser.addChoosableFileFilter( new FileNameExtensionFilter("*.zip | ZIP archive", "zip"));
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
                        if (chooser.showOpenDialog(sourcePanel) == JFileChooser.APPROVE_OPTION)
                        {
                            sourceFolderField.setText(chooser.getSelectedFile().getAbsolutePath());
                        }
                    }
                });

                JLabel oldSourcePanelLabel = new JLabel("Comparison source code (optional): ");
                final JButton oldSourceFolderBrowseButton = new JButton("Select folder or zip file...");
                JTextField oldSourceFolderField = new JTextField(30);
                callbacks.customizeUiComponent(oldSourceFolderField);
                oldSourceFolderBrowseButton.addActionListener(new ActionListener()
                {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e)
                    {
                        JFileChooser chooser = new JFileChooser();
                        String currentDirectory = oldSourceFolderField.getText();
                        if ((currentDirectory == null) || (currentDirectory.trim().equals("")))
                            currentDirectory = System.getProperty("user.home");

                        chooser.setCurrentDirectory(new java.io.File(currentDirectory));
                        chooser.setDialogTitle("Please select the folder or zip file containing the source code");
                        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
                        chooser.setAcceptAllFileFilterUsed(false);
                        chooser.addChoosableFileFilter( new FileNameExtensionFilter("*.zip | ZIP archive", "zip"));
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
                        if (chooser.showOpenDialog(sourcePanel) == JFileChooser.APPROVE_OPTION)
                        {
                            oldSourceFolderField.setText(chooser.getSelectedFile().getAbsolutePath());;
                        }
                    }
                });

                GridBagLayout experimentLayout = new GridBagLayout();
                GridBagConstraints labelConstraints = new GridBagConstraints();
                labelConstraints.gridwidth = 1;
                labelConstraints.gridx = 0;
                labelConstraints.gridy = 0;
                labelConstraints.fill = GridBagConstraints.HORIZONTAL;

                GridBagConstraints textBoxConstraints = new GridBagConstraints();
                textBoxConstraints.gridwidth = 4;
                textBoxConstraints.gridx = 1;
                textBoxConstraints.gridy = 0;
                textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;

                GridBagConstraints browseButtonConstraints = new GridBagConstraints();
                browseButtonConstraints.gridwidth = 1;
                browseButtonConstraints.gridx = 5;
                browseButtonConstraints.gridy = 0;
                browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

                JPanel myPanel = new JPanel();
                myPanel.setLayout(experimentLayout);
                myPanel.add(sourcePanelLabel, labelConstraints);
                myPanel.add(sourceFolderField, textBoxConstraints);
                myPanel.add(sourceFolderBrowseButton, browseButtonConstraints);

                labelConstraints = new GridBagConstraints();
                labelConstraints.gridwidth = 1;
                labelConstraints.gridx = 0;
                labelConstraints.gridy = 1;
                labelConstraints.fill = GridBagConstraints.HORIZONTAL;

                textBoxConstraints = new GridBagConstraints();
                textBoxConstraints.gridwidth = 4;
                textBoxConstraints.gridx = 1;
                textBoxConstraints.gridy = 1;
                textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;

                browseButtonConstraints = new GridBagConstraints();
                browseButtonConstraints.gridwidth = 1;
                browseButtonConstraints.gridx = 5;
                browseButtonConstraints.gridy = 1;
                browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

                myPanel.setLayout(experimentLayout);
                myPanel.add(oldSourcePanelLabel, labelConstraints);
                myPanel.add(oldSourceFolderField, textBoxConstraints);
                myPanel.add(oldSourceFolderBrowseButton, browseButtonConstraints);

                sourcePanel.setLayout(new GridBagLayout());
                GridBagConstraints panelConstraints = new GridBagConstraints();
                panelConstraints.gridwidth = 1;
                panelConstraints.gridx = 0;
                panelConstraints.gridy = 0;
                panelConstraints.fill = GridBagConstraints.HORIZONTAL;

                sourcePanel.add(myPanel, panelConstraints);

                int result = JOptionPane.showConfirmDialog(view,
                        sourcePanel,
                        "Please enter the source code location",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.INFORMATION_MESSAGE);
                if (result == JOptionPane.OK_OPTION)
                {
                    String sourcePath = sourceFolderField.getText();
                    String oldSourcePath = oldSourceFolderField.getText();
                    if(sourcePath != null && !sourcePath.trim().isEmpty())
                    {
                        BurpPropertiesManager.getBurpPropertiesManager().setSourceFolder(sourcePath);
                        BurpPropertiesManager.getBurpPropertiesManager().setOldSourceFolder(oldSourcePath);
                        return true;
                    }
                    else
                        return false;
                }
                else
                    return false;
            }

            return shouldContinue;
        }
	}

