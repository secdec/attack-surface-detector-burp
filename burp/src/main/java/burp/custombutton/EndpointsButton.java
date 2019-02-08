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
package burp.custombutton;

import burp.*;
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
public abstract class EndpointsButton extends JButton
{
    public static int mode;
    public static final String GENERIC_INT_SEGMENT = "\\{id\\}";
    public EndpointsButton(final Component view, final IBurpExtenderCallbacks callbacks, int mode)
    {
        this.mode = mode;
        setText(getButtonText());
        addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                boolean configured = false;
                if(mode == 0)
                    configured = ConfigurationDialogs.showSource(view, getDialogMode());
                else if(mode == 1)
                    configured = ConfigurationDialogs.showJson(view, getDialogMode());
                boolean makeReqs = true;
                boolean completed = false;
                java.util.List<String> nodes = new ArrayList<>();
                if (configured)
                {
                    if (BurpPropertiesManager.getBurpPropertiesManager().getConfigFile() != null )
                        callbacks.loadConfigFromJson(getBurpConfigAsString());
                    try
                    {
                        EndpointDecorator[] endpoints = getEndpoints(view, false);
                        EndpointDecorator[] comparePoints = null;
                        if(BurpPropertiesManager.getBurpPropertiesManager().getOldSourceFolder()!= null && !BurpPropertiesManager.getBurpPropertiesManager().getOldSourceFolder().trim().isEmpty() && mode == 0)
                            comparePoints = getEndpoints(view, true);
                        else if(BurpPropertiesManager.getBurpPropertiesManager().getOldSerializationFile()!= null && !BurpPropertiesManager.getBurpPropertiesManager().getOldSerializationFile().trim().isEmpty() && mode == 1)
                            comparePoints = getEndpoints(view, true);
                        if (endpoints.length == 0)
                            JOptionPane.showMessageDialog(view, getNoEndpointsMessage(), "Warning", JOptionPane.WARNING_MESSAGE);
                        else
                        {
                            if (comparePoints != null && comparePoints.length != 0)
                                endpoints = compareEndpoints(endpoints, comparePoints, view);

                            fillEndpointsToTable(endpoints);
                            for (EndpointDecorator decorator : endpoints)
                            {
                                if (decorator != null)
                                {
                                    Endpoint.Info endpoint = decorator.getEndpoint();
                                    String endpointPath = endpoint.getUrlPath();
                                    if (endpointPath.startsWith("/"))
                                        endpointPath = endpointPath.substring(1);

                                    endpointPath = endpointPath.replaceAll(GENERIC_INT_SEGMENT, "1");
                                    nodes.add(endpointPath);
                                    for(Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
                                        nodes.add(endpointPath + "?" + parameter.getKey() + "=" + parameter.getValue());
                                }
                            }
                            String url = UrlDialog.show(view);
                            if (url != null)
                            {
                                try
                                {
                                    if (!url.substring(url.length() - 1).equals("/"))
                                        url = url+"/";

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

                                if (completed)
                                    JOptionPane.showMessageDialog(view, getCompletedMessage());
                            }
                            else
                                makeReqs = false;
                        }

                        if(makeReqs)
                        {
                            if (BurpPropertiesManager.getBurpPropertiesManager().getAutoScan())
                                sendToScanner(callbacks, UrlDialog.show(view));
                            RequestMakerThread rmt = new RequestMakerThread(callbacks, view);
                            new Thread(rmt).start();
                        }
                    }
                    catch(Exception ex)
                    {
                        JOptionPane.showMessageDialog(view, getErrorMessage());
                    }
                }
                else
                    JOptionPane.showMessageDialog(view, "The location of the source code to analyze is required to import endpoints, select the directory location in the plugin options", "Warning", JOptionPane.WARNING_MESSAGE);

            }
        });
    }

    private void sendToScanner(IBurpExtenderCallbacks callbacks, String url)
    {
        IHttpRequestResponse[] responses = callbacks.getSiteMap(url);
        for (IHttpRequestResponse response : responses)
        {
            IHttpService service = response.getHttpService();
            boolean useHttps = service.getProtocol().equalsIgnoreCase("https");
            callbacks.doActiveScan(service.getHost(), service.getPort(), useHttps, response.getRequest());
        }
    }

    private String getBurpConfigAsString()
    {
        try
        {
            JSONParser parser = new JSONParser();
            JSONObject jsonObject = (JSONObject) parser.parse(new FileReader(BurpPropertiesManager.getBurpPropertiesManager().getConfigFile()));
            return jsonObject.toJSONString();
        }
        catch (ParseException e)
        {
            e.printStackTrace();
        } catch (FileNotFoundException e)
        {
            e.printStackTrace();
        } catch (IOException e)
        {
            e.printStackTrace();
        }
        return "";
    }

    private void fillEndpointsToTable(EndpointDecorator[] decorators)
    {
        int count = 0;
        JTable endpointTable = BurpPropertiesManager.getBurpPropertiesManager().getEndpointsTable();
        DefaultTableModel dtm = (DefaultTableModel)endpointTable.getModel();
        while(dtm.getRowCount() > 0)
            dtm.removeRow(0);

        for (EndpointDecorator decorator : decorators)
        {
            Endpoint.Info endpoint = decorator.getEndpoint();
            boolean hasGet = false;
            boolean hasPost = false;
            String method = endpoint.getHttpMethod();
            if(method.toString().equalsIgnoreCase("post"))
                hasPost = true;
            else if (method.toString().equalsIgnoreCase("get"))
                hasGet = true;
            dtm.addRow(new Object[]{endpoint.getUrlPath(), endpoint.getParameters().size(), hasGet, hasPost,
                    (decorator.getStatus() == EndpointDecorator.Status.NEW || decorator.getStatus() == EndpointDecorator.Status.CHANGED), decorator});
            count++;
        }
        JLabel countLabel = BurpPropertiesManager.getBurpPropertiesManager().getCountLabel();
        countLabel.setVisible(true);
        countLabel.setText("Total Endpoints Detected: " + count);
    }

    private void buildRequests(final Component view, final IBurpExtenderCallbacks callbacks, EndpointDecorator[] decorators, String url) {
        HashMap<RequestDecorator, IHttpService> requests = new HashMap<RequestDecorator, IHttpService>();
        for (EndpointDecorator decorator : decorators)
        {
            Endpoint.Info endpoint = decorator.getEndpoint();
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
                    for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
                    {
                        if (first)
                        {
                            first = false;
                            reqString = reqString + "?";
                        }
                        else
                            reqString = reqString + "&";

                        if (parameter.getValue().getDataType() == ParameterDataType.STRING)
                            reqString = reqString + parameter.getKey() + "="+"debug";

                        else if (parameter.getValue().getDataType() == ParameterDataType.INTEGER)
                            reqString = reqString + parameter.getKey() + "="+"-1";

                        else if (parameter.getValue().getDataType() == ParameterDataType.BOOLEAN)
                            reqString = reqString + parameter.getKey() + "="+"true";

                        else if (parameter.getValue().getDataType() == ParameterDataType.DECIMAL)
                            reqString = reqString + parameter.getKey() + "="+".1";

                        else if (parameter.getValue().getDataType() == ParameterDataType.DATE_TIME)
                            reqString = reqString + parameter.getKey() + "="+ new Date();

                        else if (parameter.getValue().getDataType() == ParameterDataType.LOCAL_DATE)
                            reqString = reqString + parameter.getKey() + "="+new Date();

                    }
                    byte[] manReq = callbacks.getHelpers().buildHttpRequest(new URL(url + reqString));
                    if(method.toString().equalsIgnoreCase("requestmethod.post") || method.toString().equalsIgnoreCase("post"))
                        manReq = callbacks.getHelpers().toggleRequestMethod(manReq);

                    requests.put(new RequestDecorator(manReq, decorator.getStatus()), callbacks.getHelpers().buildHttpService(reqUrl.getHost(), reqUrl.getPort(), reqUrl.getProtocol()));
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

    private EndpointDecorator[] compareEndpoints(EndpointDecorator[] decorators, EndpointDecorator[] comparePoints, final Component view)
    {
        for(EndpointDecorator decorator : decorators)
        {
            EndpointDecorator.Status newStat = EndpointDecorator.Status.NEW;
            for(EndpointDecorator comparePointDec : comparePoints)
            {
                if (decorator.getEndpoint().getUrlPath().equals(comparePointDec.getEndpoint().getUrlPath()) && decorator.getEndpoint().getHttpMethod().equals(comparePointDec.getEndpoint().getHttpMethod()))
                {
                    if (decorator.checkSum() != comparePointDec.checkSum())
                    {
                        newStat = EndpointDecorator.Status.CHANGED;
                        decorator.setComparePoint(comparePointDec.getEndpoint());
                        break;
                    }
                    else
                    {
                        newStat = EndpointDecorator.Status.UNCHANGED;
                        break;
                    }
                }
            }
            decorator.setStatus(newStat);
        }

        return decorators;
    }


    protected abstract String getButtonText();

    protected abstract String getNoEndpointsMessage();

    protected abstract String getCompletedMessage();

    protected abstract String getErrorMessage();

    protected abstract ConfigurationDialogs.DialogMode getDialogMode();

    protected abstract EndpointDecorator[] getEndpoints(final Component view, boolean compare);


}
