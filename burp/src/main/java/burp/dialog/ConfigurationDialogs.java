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
import java.awt.*;
import java.awt.event.ActionListener;

public class ConfigurationDialogs {

    public static enum DialogMode {
         SOURCE;
    }

	public ConfigurationDialogs() {}
	
	public static boolean show(Component view, DialogMode mode) {
        //boolean shouldContinue = false;
            boolean shouldContinue = (!BurpPropertiesManager.getBurpPropertiesManager().getSourceFolder().trim().isEmpty());
            if(!shouldContinue)
            {
                JPanel sourcePanel = new JPanel();
                JLabel sourcePanelDescription = new JLabel("This setting lets you configure the location of your source code.");
                JLabel sourcePanelLabel = new JLabel("Location of source code folder                                         ");
                final JButton sourceFolderBrowseButton = new JButton("Select folder ...");
                JTextField sourceFolderField = new JTextField();
                IBurpExtenderCallbacks callbacks =  BurpPropertiesManager.getBurpPropertiesManager().getCallbacks();
                callbacks.customizeUiComponent(sourceFolderField);
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
                        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                        chooser.setAcceptAllFileFilterUsed(false);
                        if (chooser.showOpenDialog(sourcePanel) == JFileChooser.APPROVE_OPTION) {
                            sourceFolderField.setText(chooser.getSelectedFile().getAbsolutePath());
                            BurpPropertiesManager.getBurpPropertiesManager().setSourceFolder(sourceFolderField.getText());
                        }
                    }
                });

                GridBagConstraints labelConstraints = new GridBagConstraints();
                //labelConstraints.gridwidth = 1;
                //labelConstraints.gridx = 0;
                //labelConstraints.gridy = 0;
                //labelConstraints.fill = GridBagConstraints.HORIZONTAL;

                GridBagLayout experimentLayout = new GridBagLayout();

                sourcePanel.setLayout(experimentLayout);
                //sourcePanel.add(sourcePanelDescription,labelConstraints);

                labelConstraints = new GridBagConstraints();
                labelConstraints.gridwidth = 1;
                labelConstraints.gridx = 0;
                labelConstraints.gridy = 0;
                labelConstraints.fill = GridBagConstraints.HORIZONTAL;
                sourcePanel.add(sourcePanelLabel, labelConstraints);

                GridBagConstraints textBoxConstraints = new GridBagConstraints();
                textBoxConstraints.gridwidth = 4;
                textBoxConstraints.gridx = 0;
                textBoxConstraints.gridy = 1;
                textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;
                sourcePanel.add(sourceFolderField, textBoxConstraints);

                textBoxConstraints = new GridBagConstraints();
                textBoxConstraints.gridwidth = 4;
                textBoxConstraints.gridx = 1;
                textBoxConstraints.gridy = 1;
                textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;
                sourcePanel.add(sourceFolderBrowseButton, textBoxConstraints);

                int result = JOptionPane.showConfirmDialog(view,
                        sourcePanel,
                        "Please enter the source code location",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.INFORMATION_MESSAGE);
                if (result == JOptionPane.OK_OPTION) {
                    String sourcePath = sourceFolderField.getText();
                    if(sourcePath != null && !sourcePath.trim().isEmpty())
                    {
                        BurpPropertiesManager.getBurpPropertiesManager().setSourceFolder(sourcePath);
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                    {
                    return false;
                }

            }

            return shouldContinue;
        }
	}


