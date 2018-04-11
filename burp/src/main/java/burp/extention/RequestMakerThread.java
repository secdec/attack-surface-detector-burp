////////////////////////////////////////////////////////////////////////////////////////
//
//     Copyright (C) 2017 Applied Visions - http://securedecisions.com
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
//     This material is based on research sponsored by the Department of Homeland
//     Security (DHS) Science and Technology Directorate, Cyber Security Division
//     (DHS S&T/CSD) via contract number HHSP233201600058C.
//
//     Contributor(s):
//              Secure Decisions, a division of Applied Visions, Inc
//
////////////////////////////////////////////////////////////////////////////////////////
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


