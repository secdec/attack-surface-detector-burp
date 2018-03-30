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

import burp.extention.BurpPropertiesManager;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class UrlDialog {

    public static boolean https;
    public static String show(Component view) {
        BurpPropertiesManager burpPropertiesManager = BurpPropertiesManager.getBurpPropertiesManager();
        String targetHost = burpPropertiesManager.getTargetHost();
        String targetPort = burpPropertiesManager.getTargetPort();
        String targetPath = burpPropertiesManager.getTargetPath();
        String targetProto = new String();

        if(burpPropertiesManager.getUseHttps())
            targetProto = "https://";
        else
            targetProto = "http://";

        if(targetHost != null && !targetHost.trim().isEmpty() && targetPort != null && !targetPort.trim().isEmpty())
        {
            if(targetPath != null && !targetPath.trim().isEmpty())
                return targetProto+ targetHost  + ":" + targetPort + "/" + targetPath;
            else
                return targetProto+ targetHost  + ":" + targetPort;
        }


        JTextField hostField = new JTextField(40);
        JTextField portField = new JTextField(40);
        JTextField pathField = new JTextField(40);
        hostField.setText(BurpPropertiesManager.getBurpPropertiesManager().getTargetHost());
        portField.setText(BurpPropertiesManager.getBurpPropertiesManager().getTargetPort());
        pathField.setText(BurpPropertiesManager.getBurpPropertiesManager().getTargetPath());

        JLabel panelLabel = new JLabel("URL configuration is required to populate the site map with the detected endpoints" + '\n');
        panelLabel.setForeground(Color.DARK_GRAY);
       JCheckBox httpsField = new JCheckBox();
       httpsField.setSelected(BurpPropertiesManager.getBurpPropertiesManager().getUseHttps());

        ActionListener applicationCheckBoxHttpActionListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                BurpPropertiesManager.getBurpPropertiesManager().setUseHttps(httpsField.isSelected());
                BurpPropertiesManager.getBurpPropertiesManager().getUseHttpsField().setSelected(true);
            }
        };

        httpsField.addActionListener(applicationCheckBoxHttpActionListener);

        PlainDocument portDoc = (PlainDocument)portField.getDocument();
        portDoc.setDocumentFilter(new PortFilter());


        GridBagLayout experimentLayout = new GridBagLayout();
        GridBagConstraints labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 0;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        GridBagConstraints textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 1;
        textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;

        GridBagLayout panelLayout = new GridBagLayout();
        GridBagConstraints panelConstraints = new GridBagConstraints();
        panelConstraints.gridwidth = 1;
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 0;
        panelConstraints.fill = GridBagConstraints.HORIZONTAL;

        JPanel myPanel = new JPanel();
        JPanel myBase = new JPanel();
        JPanel labelPanel = new JPanel();
        myBase.setLayout(panelLayout);

        labelPanel.add(panelLabel);

        myBase.add(labelPanel,panelConstraints);


        panelConstraints = new GridBagConstraints();
        panelConstraints.gridwidth = 1;
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 1;
        panelConstraints.fill = GridBagConstraints.HORIZONTAL;


        myBase.add(myPanel,panelConstraints);
        myPanel.setLayout(experimentLayout);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 1;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(new JLabel("Host"), labelConstraints);
        myPanel.add(hostField, textBoxConstraints);






        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 2;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;
        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 2;
        textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(new JLabel("Port"), labelConstraints);
        myPanel.add(portField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 3;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;
        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 3;
        textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(new JLabel("Path (optional)"), labelConstraints);
        myPanel.add(pathField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 4;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;
        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 4;
        textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(new JLabel("Use Https"), labelConstraints);
        myPanel.add(httpsField, textBoxConstraints);



        String attempt = UrlDialog.class.getProtectionDomain().getCodeSource().getLocation().getFile() + "/dg-icon.png";

        ImageIcon icon = new ImageIcon(attempt);

        String[] options = new String[2];
        options[0] = new String("Submit");
        options[1] = new String("Skip");

        int result = JOptionPane.showOptionDialog(view, myBase, "Target URL Configuration", JOptionPane.YES_NO_OPTION,JOptionPane.INFORMATION_MESSAGE,icon,options,null);
        if (result == JOptionPane.YES_OPTION) {
            String host = hostField.getText();
            String port = portField.getText();
            String path = pathField.getText();
            String proto;

            if(burpPropertiesManager.getUseHttps())
                proto = "https://";
            else
                proto = "http://";

            String url = new String();
            if(host != null && !host.trim().isEmpty() && port != null && !port.trim().isEmpty())
            {
                if(path != null && !path.trim().isEmpty())
                    url = proto+ host  + ":" + port + "/" + path;
                else
                    url = proto+ host  + ":" + port;
            }
            if (url != null && !url.isEmpty())
            {
                burpPropertiesManager.setTargetUrl(url);
                burpPropertiesManager.setTargetPort(port);
                burpPropertiesManager.setTargetHost(host);
                burpPropertiesManager.setTargetPath(path);
            }
            else
            {
                burpPropertiesManager.setTargetUrl(url);
                burpPropertiesManager.setTargetPort(port);
                burpPropertiesManager.setTargetHost(host);
                burpPropertiesManager.setTargetPath(path);
               // burpPropertiesManager.setUseHttps(https);
                return null;
            }
            return url;
        } else {
            return null;
        }
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

        if (test(sb.toString()) && sb.length() <= maxLength && val <= 65535) {
            super.insertString(fb, offset, string, attr);
        } else {
            Toolkit.getDefaultToolkit().beep();
        }
    }

    private boolean test(String text) {
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

        if (test(sb.toString()) && (sb.length() <= maxLength) && val <= 65535) {
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

        if ((test(sb.toString()) && (sb.length() <= maxLength)) || (sb.length() == 0)) {
            super.remove(fb, offset, length);
        } else {
            Toolkit.getDefaultToolkit().beep();
        }

    }
}