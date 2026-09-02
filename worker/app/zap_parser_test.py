from app.scanner.parsers.zap_parser import ZAPParser


ZAP_XML = """<?xml version="1.0"?>
<OWASPZAPReport programName="ZAP" version="2.17.0">
    <site name="https://example.com" host="example.com" port="443" ssl="true">
        <alerts>
            <alertitem>
                <pluginid>10038</pluginid>
                <alertRef>10038-1</alertRef>
                <alert>Content Security Policy (CSP) Header Not Set</alert>
                <name>Content Security Policy (CSP) Header Not Set</name>
                <riskcode>2</riskcode>
                <confidence>3</confidence>
                <riskdesc>Medium (High)</riskdesc>
                <desc>
                    &lt;p&gt;Content Security Policy is not configured.&lt;/p&gt;
                </desc>
                <instances>
                    <instance>
                        <uri>https://example.com</uri>
                        <nodeName>https://example.com</nodeName>
                        <method>GET</method>
                        <param></param>
                        <attack></attack>
                        <evidence></evidence>
                    </instance>
                </instances>
                <solution>
                    &lt;p&gt;Configure the Content-Security-Policy header.&lt;/p&gt;
                </solution>
                <reference>
                    &lt;p&gt;https://developer.mozilla.org/&lt;/p&gt;
                </reference>
                <cweid>693</cweid>
                <wascid>15</wascid>
            </alertitem>
        </alerts>
    </site>
</OWASPZAPReport>
"""


parser = ZAPParser()
result = parser.parse(ZAP_XML)

print("Scanner:", result["scanner"])
print("Assets:", len(result["assets"]))
print("Findings:", len(result["findings"]))

print("\nFirst finding:")
print(result["findings"][0])