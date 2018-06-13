![asd-logo](https://user-images.githubusercontent.com/35819157/41377103-1105060c-6f29-11e8-810c-0ec520330a58.png)

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

To see a brief demonstration for the Attack Surface Detector, you can check it out [here:](https://youtu.be/jUUJNRcmqwI)

## Extension Details
* Extension Type: Java
* Extension File: attacksurfacedetector-release-#-jar-with-dependencies

### Burp Suite Professional
* Scanner functionality available.
* The plugin will run source code analysis and seed endpoints into the target sitemap, and optionally run the spider and active scanning functionality.
### Burp Suire Free
* Scanner unavailable
* Plugin will run source code analysis and send seeded endpoints to *Target* and *Spider*; Scanner will not run



## Installation
[Detailed install instructions](https://github.com/secdec/attack-surface-detector-burp/wiki/Installation).

# For Developers & Contributors

## Build Instructions
1. Install Maven. - [https://maven.apache.org/install.html](https://maven.apache.org/install.html)
2. Clone Attack Surface Detector repository - https://github.com/secdec/attack-surface-detector-burp 
3. Navigate to the Source Code Directory
4. Open a new terminal and run the command `mvn clean package`
4. The plugin will be located in the target folder named attacksurfacedetector-release-#-jar-with-dependencies.jar

## License

Licensed under the [MPL](https://github.com/secdec/attack-surface-detector-burp/blob/master/LICENSE) License.






