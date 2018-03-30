package burp.extention;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import jdk.nashorn.internal.scripts.JO;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class RequestMakerThread implements Runnable
{
    private IBurpExtenderCallbacks callbacks;
    private Component view;

    public RequestMakerThread(IBurpExtenderCallbacks callbacks, Component view)
    {
        this.callbacks = callbacks;
    }

    public void run()
    {
        try
        {
            HashMap<byte[], IHttpService> requests = BurpPropertiesManager.getBurpPropertiesManager().getRequests();
            Set<Map.Entry<byte[], IHttpService>> st = requests.entrySet();
            int i = 1;
            for (Map.Entry<byte[], IHttpService> me : st)
            {
                IHttpRequestResponse reqRep = callbacks.makeHttpRequest(me.getValue(),me.getKey());
                reqRep.setHighlight("cyan");
                reqRep.setComment("Generated from source code analysis");
                callbacks.addToSiteMap(reqRep);

            }
        }
        catch(Exception e)
        {
            JOptionPane.showMessageDialog(view, e.getMessage(),
                    "Warning", JOptionPane.WARNING_MESSAGE);
        }
    }
}


