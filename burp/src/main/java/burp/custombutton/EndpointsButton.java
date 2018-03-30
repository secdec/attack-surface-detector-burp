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
//     Contributor(s):
//              Denim Group, Ltd.
//              Secure Decisions, a division of Applied Visions, Inc
//
////////////////////////////////////////////////////////////////////////

package burp.custombutton;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.dialog.ConfigurationDialogs;
import burp.dialog.UrlDialog;
import burp.extention.BurpPropertiesManager;
import burp.extention.RequestMakerThread;
import com.denimgroup.threadfix.data.entities.RouteParameter;
import com.denimgroup.threadfix.data.enums.ParameterDataType;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 12/30/13
 * Time: 2:28 PM
 * To change this template use File | Settings | File Templates.
 */
public abstract class EndpointsButton extends JButton {

    public static final String GENERIC_INT_SEGMENT = "\\{id\\}";

    public EndpointsButton(final Component view, final IBurpExtenderCallbacks callbacks) {
        setText(getButtonText());
        addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                boolean configured = ConfigurationDialogs.show(view, getDialogMode());
                boolean makeReqs = true;
                boolean completed = false;
                java.util.List<String> nodes = new ArrayList<>();
                if (configured) {
                    if (BurpPropertiesManager.getBurpPropertiesManager().getConfigFile() != null ) {
                        callbacks.loadConfigFromJson(getBurpConfigAsString());
                    }
                    Endpoint.Info[] endpoints = getEndpoints();
                    logEndpoints(view, endpoints);
                    fillEndpointsToTable(endpoints);
                    if (endpoints.length == 0) {
                        JOptionPane.showMessageDialog(view, getNoEndpointsMessage(), "Warning",
                                JOptionPane.WARNING_MESSAGE);

                    } else {
                        for (Endpoint.Info endpoint : endpoints) {
                            if (endpoint != null) {
                                String endpointPath = endpoint.getUrlPath();
                                if (endpointPath.startsWith("/")) {
                                    endpointPath = endpointPath.substring(1);
                                }
                                endpointPath = endpointPath.replaceAll(GENERIC_INT_SEGMENT, "1");
                                nodes.add(endpointPath);

                                for(Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet()) {
                                    nodes.add(endpointPath + "?" + parameter.getKey() + "=" + parameter.getValue());
                                }

                            }
                        }

                        String url = UrlDialog.show(view);

                        if (url != null) {
                            try {
                                if (!url.substring(url.length() - 1).equals("/")) {
                                    url = url+"/";
                                }
                                for (String node: nodes)
                                {
                                    URL nodeUrl = new URL(url + node);
                                    callbacks.includeInScope(nodeUrl);
                                    if(BurpPropertiesManager.getBurpPropertiesManager().getAutoSpider())
                                        callbacks.sendToSpider(nodeUrl);
                                }
                                buildRequests(view, callbacks, endpoints, url);
                                completed = true;
                            }
                            catch (MalformedURLException e1)
                            {
                                JOptionPane.showMessageDialog(view, "Invalid URL.",
                                        "Warning", JOptionPane.WARNING_MESSAGE);
                            }

                            if (completed) {
                                JOptionPane.showMessageDialog(view, getCompletedMessage());
                            }
                    }
                        else
                            {
                                makeReqs = false;
                            }
                    }

                    if(makeReqs) {
                        if (BurpPropertiesManager.getBurpPropertiesManager().getAutoScan())
                            sendToScanner(callbacks, UrlDialog.show(view));
                        RequestMakerThread rmt = new RequestMakerThread(callbacks, view);
                        new Thread(rmt).start();
                    }
                }
                else
                {
                    JOptionPane.showMessageDialog(view, "The location of the source code to analyze is required to import endpoints, select the directory location in the plugin options",
                            "Warning", JOptionPane.WARNING_MESSAGE);
                }

            }//right here?
        });
    }

    private void sendToScanner(IBurpExtenderCallbacks callbacks, String url) {
        IHttpRequestResponse[] responses = callbacks.getSiteMap(url);
        for (IHttpRequestResponse response : responses) {
            IHttpService service = response.getHttpService();
            boolean useHttps = service.getProtocol().equalsIgnoreCase("https");
            callbacks.doActiveScan(service.getHost(), service.getPort(), useHttps, response.getRequest());
        }
    }

    private String getBurpConfigAsString() {
        try {
            JSONParser parser = new JSONParser();
            JSONObject jsonObject = (JSONObject) parser.parse(new FileReader(BurpPropertiesManager.getBurpPropertiesManager().getConfigFile()));

            return jsonObject.toJSONString();
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return "";
    }

    private void fillEndpointsToTable(Endpoint.Info[] endpoints)
    {
        int count = 0;
        JTable endpointTable = BurpPropertiesManager.getBurpPropertiesManager().getEndpointsTable();
        DefaultTableModel dtm = (DefaultTableModel)endpointTable.getModel();
        while(dtm.getRowCount() > 0)
        {
            dtm.removeRow(0);
        }
        for (Endpoint.Info endpoint : endpoints)
        {
            boolean hasGet = false;
            boolean hasPost = false;
            String method = endpoint.getHttpMethod();
            if(method.toString().equalsIgnoreCase("post"))
                hasPost = true;
            else if (method.toString().equalsIgnoreCase("get"))
                hasGet = true;
            dtm.addRow(new Object[]
            {
                endpoint.getUrlPath(),
                endpoint.getParameters().size(),
                hasGet,
                hasPost,
                endpoint
            });
            count++;
        }
        JLabel countLabel = BurpPropertiesManager.getBurpPropertiesManager().getCountLabel();
        countLabel.setVisible(true);
        countLabel.setText("Total Endpoints Detected: " + count);

    }

    private void buildRequests(final Component view, final IBurpExtenderCallbacks callbacks, Endpoint.Info[] endpoints, String url) {
        HashMap<byte[], IHttpService> requests = new HashMap<byte[], IHttpService>();
        for (Endpoint.Info endpoint : endpoints)
        {
            if (endpoint != null)
            {
                String endpointPath = endpoint.getUrlPath();
                if (endpointPath.startsWith("/"))
                {
                    endpointPath = endpointPath.substring(1);
                }
                endpointPath = endpointPath.replaceAll(GENERIC_INT_SEGMENT, "1");

                boolean first = true;
                String reqString = endpointPath;
                String method = endpoint.getHttpMethod();
                try
                {
                   URL reqUrl = new URL(url + endpointPath);
                   byte[] req = callbacks.getHelpers().buildHttpRequest(reqUrl);
                   for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
                   {
                       if (first)
                       {
                           first = false;
                                  reqString = reqString + "?";
                       }
                       else
                       {
                           reqString = reqString + "&";
                       }
                       IParameter param = null;

                       if (parameter.getValue().getDataType() == ParameterDataType.STRING)
                       {
                           reqString = reqString + parameter.getKey() + "="+"debug";
                       }

                       else if (parameter.getValue().getDataType() == ParameterDataType.INTEGER)
                       {
                           reqString = reqString + parameter.getKey() + "="+"-1";
                       }

                       else if (parameter.getValue().getDataType() == ParameterDataType.BOOLEAN)
                       {
                           reqString = reqString + parameter.getKey() + "="+"true";
                       }
                       else if (parameter.getValue().getDataType() == ParameterDataType.DECIMAL)
                       {
                           reqString = reqString + parameter.getKey() + "="+".1";
                       }
                       else if (parameter.getValue().getDataType() == ParameterDataType.DATE_TIME)
                       {
                           reqString = reqString + parameter.getKey() + "="+ new Date();
                       }
                       else if (parameter.getValue().getDataType() == ParameterDataType.LOCAL_DATE)
                       {
                           reqString = reqString + parameter.getKey() + "="+new Date();
                       }
                       if (param != null)
                          callbacks.getHelpers().addParameter(req, param);
                    }
                    byte[] manReq = callbacks.getHelpers().buildHttpRequest(new URL(url + reqString));
                    if(method.toString().equalsIgnoreCase("requestmethod.post") || method.toString().equalsIgnoreCase("post"))
                    {
                        manReq = callbacks.getHelpers().toggleRequestMethod(manReq);
                    }

                        requests.put(manReq, callbacks.getHelpers().buildHttpService(reqUrl.getHost(), reqUrl.getPort(), reqUrl.getProtocol()));


                 }
                 catch (MalformedURLException e1)
                 {
                     JOptionPane.showMessageDialog(view, "Invalid URL.",
                            "Warning", JOptionPane.WARNING_MESSAGE);
                 }
                 catch (Exception ge)
                 {
                     JOptionPane.showMessageDialog(view, ge.getMessage(),
                              "Warning", JOptionPane.WARNING_MESSAGE);
                 }
            }
        }
        BurpPropertiesManager.getBurpPropertiesManager().setRequests(requests);
    }

    public void logEndpoints(final Component view, Endpoint.Info[] endpoints) {
        try
        {
            FileWriter writer = new FileWriter(javax.swing.filechooser.FileSystemView.getFileSystemView().getHomeDirectory()+"/AttackSurfaceDetectorlogfile.txt", false);
            PrintWriter printer = new PrintWriter(writer);
            for(Endpoint.Info endpoint : endpoints)
            {
                printer.printf("%s" + "%n", endpoint.getUrlPath());
            }

            printer.close();

        }
        catch (Exception ge)
        {
            JOptionPane.showMessageDialog(view, ge.getMessage(),"Warning", JOptionPane.WARNING_MESSAGE);
        }
    }
    protected abstract String getButtonText();

    protected abstract String getNoEndpointsMessage();

    protected abstract String getCompletedMessage();

    protected abstract ConfigurationDialogs.DialogMode getDialogMode();

    protected abstract Endpoint.Info[] getEndpoints();
}
