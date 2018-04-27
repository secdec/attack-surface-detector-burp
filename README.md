# Summary
During web application penetration testing, it is important to enumerate  your application's attack surface. While Dynamic Application Security Testing (DAST) tools (such as Burp Suite and ZAP) are good at spidering to identify application attack surfaces, they will often fail to identify unlinked endpoints and optional parameters. These endpoints and parameters not found often go untested, which can leave your application open to an attacker.
This tool is the Attack Surface Detector, a plugin for Burp Suite. This tool figures out the endpoints of a web application, the parameters these endpoints accept, and the data type of those parameters. This includes the unlinked endpoints a spider won't find in client-side code, or optional parameters totally unused in client-side code. The plugin then imports this data into Burp Suite so you view the results, or work with the detected endpoints and parameters from the target site map.

# How it Works
The Attack Surface Detector uses static code analyses to identify web app endpoints by parsing routes and identifying parameters (with supported languages and frameworks). NOTE: Multiple parsers are needed to support different languages and frameworks.
## Supported Frameworks:
  * C# / ASP.NET MVC
  * C# / Web Forms
  * Java / Spring MVC
  * Java / Struts
  * Java JSP
  * Python / Django
  * Ruby / Rails

To see a brief demonstration for the Attack Surface Detector, you can check it out here:[YouTube Link](https://youtu.be/jUUJNRcmqwI)

# Building the Plugin

1.  Install *Maven*:  https://maven.apache.org/install.html
2. Clone *Attack Surface Detector* repository:  https://github.com/secdec/attack-surface-detector-burp
3. Navigate to the source code *Directory*, open terminal and run the command `mvn clean package`
4. The plugin will be located in the target folder named *attacksurfacedetector-release-1-jar-with-dependencies*.

# Installation

## Requirements
* This plugin
* PortSwigger Burp Suite

## How to Install

1.	Download and install the latest build of PortSwigger BurpSuite from http://portswigger.net/burp/ 
### Professional
* Scanner functionality available.
* The plugin will run source code analysis and seed endpoints into the target sitemap, and optionally run the spider and active scanning functionality.
### Free
* Scanner unavailable
* Plugin will run source code analysis and send seeded endpoints to *Target* and *Spider*; Scanner will not run
2.	Launch application

### Installing the Plugin
1.	Go to *Extender* tab > *Extensions* subtab > Add in *Burp Extensions* section
#### Extension Details
* Extension Type: Java
* Extension File: attacksurfacedetector-release-1-jar-with-dependencies
* All other fields can be left alone
2.	Click *Next* and *Close*




