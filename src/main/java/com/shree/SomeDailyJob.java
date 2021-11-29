package com.shree;

import java.io.IOException;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.HTreeMap;
import org.mapdb.Serializer;
import org.mapdb.HTreeMap.KeySet;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class SomeDailyJob implements Runnable {
    static HashMap<String, ArrayList<String>> data = new HashMap<String, ArrayList<String>>();

    void phishTank() throws IOException {
        HttpURLConnection connection;
        String xml = "<taxii_11:Poll_Request xmlns:taxii_11=\"http://taxii.mitre.org/messages/taxii_xml_binding-1.1\" message_id=\"42158\" collection_name=\"guest.phishtank_com\"><taxii_11:Exclusive_Begin_Timestamp>2017-12-19T00:00:00Z</taxii_11:Exclusive_Begin_Timestamp><taxii_11:Inclusive_End_Timestamp>2017-12-19T12:00:00Z</taxii_11:Inclusive_End_Timestamp><taxii_11:Poll_Parameters allow_asynch=\"false\"><taxii_11:Response_Type>FULL</taxii_11:Response_Type> </taxii_11:Poll_Parameters></taxii_11:Poll_Request>";
        URL url = new URL("http://hailataxii.com/taxii-discovery-service");
        connection = (HttpURLConnection) url.openConnection();

        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/xml");
        connection.setRequestProperty("Accept", "application/xml");
        connection.setRequestProperty("X-TAXII-Services", "urn:taxii.mitre.org:services:1.1");
        connection.setRequestProperty("X-TAXII-Protocol", "urn:taxii.mitre.org:protocol:http:1.0");
        connection.setRequestProperty("Proxy-Connection", "keep-alive");
        connection.setRequestProperty("Host", "taxiitest.mitre.org");
        connection.setRequestProperty("X-TAXII-Content-Type", "urn:taxii.mitre.org:message:xml:1.1");
        connection.setRequestProperty("X-TAXII-Accept", "urn:taxii.mitre.org:message:xml:1.1");
        connection.setRequestProperty("X-TAXII-Content-Types", "urn:taxii.mitre.org:message:xml:1.0");
        connection.setDoOutput(true);
        connection.setConnectTimeout(1000000);
        connection.setReadTimeout(1000000);

        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = xml.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        BufferedReader reader;
        String line;
        StringBuffer res = new StringBuffer();

        int status = connection.getResponseCode();
        if (status > 200) {
            reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            while ((line = reader.readLine()) != null) {
                res.append(line);
            }
            reader.close();
        } else {
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            while ((line = reader.readLine()) != null) {
                res.append(line);
            }
            reader.close();
        }
        Document document = convertStringToXMLDocument(res.toString());
        document.getDocumentElement().normalize();
        NodeList nList = document.getElementsByTagName("cybox:Observable");
        for (int n = 0; n < nList.getLength(); n++) {
            if (nList.item(n).hasChildNodes()) {
                Node node = nList.item(n);
                Element element = (Element) node;
                if (element.getElementsByTagName("cybox:Title").item(0) != null) {
                    if (data.containsKey("url")) {
                        Element element2 = (Element) element.getElementsByTagName("cybox:Object").item(0);
                        Element element3 = (Element) element2.getElementsByTagName("cybox:Properties").item(0);
                        String str = element3.getElementsByTagName("URIObj:Value").item(0).getTextContent();

                        data.get("url").add(str);
                    } else {
                        Element element2 = (Element) element.getElementsByTagName("cybox:Object").item(0);
                        Element element3 = (Element) element2.getElementsByTagName("cybox:Properties").item(0);
                        String str = element3.getElementsByTagName("URIObj:Value").item(0).getTextContent();
                        ArrayList<String> da = new ArrayList<String>();
                        da.add(str);
                        data.put("url", da);
                    }
                }

            }

        }
    }

    void abuseCH() throws IOException {
        HttpURLConnection connection;
        String xml = "<taxii_11:Poll_Request xmlns:taxii_11=\"http://taxii.mitre.org/messages/taxii_xml_binding-1.1\" message_id=\"42158\" collection_name=\"guest.Abuse_ch\"><taxii_11:Exclusive_Begin_Timestamp>2017-11-19T00:00:00Z</taxii_11:Exclusive_Begin_Timestamp><taxii_11:Inclusive_End_Timestamp>2017-12-19T12:00:00Z</taxii_11:Inclusive_End_Timestamp><taxii_11:Poll_Parameters allow_asynch=\"false\"><taxii_11:Response_Type>FULL</taxii_11:Response_Type> </taxii_11:Poll_Parameters></taxii_11:Poll_Request>";
        URL url = new URL("http://hailataxii.com/taxii-discovery-service");
        connection = (HttpURLConnection) url.openConnection();

        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/xml");
        connection.setRequestProperty("Accept", "application/xml");
        connection.setRequestProperty("X-TAXII-Services", "urn:taxii.mitre.org:services:1.1");
        connection.setRequestProperty("X-TAXII-Protocol", "urn:taxii.mitre.org:protocol:http:1.0");
        connection.setRequestProperty("Proxy-Connection", "keep-alive");
        connection.setRequestProperty("Host", "taxiitest.mitre.org");
        connection.setRequestProperty("X-TAXII-Content-Type", "urn:taxii.mitre.org:message:xml:1.1");
        connection.setRequestProperty("X-TAXII-Accept", "urn:taxii.mitre.org:message:xml:1.1");
        connection.setRequestProperty("X-TAXII-Content-Types", "urn:taxii.mitre.org:message:xml:1.0");
        connection.setDoOutput(true);
        connection.setConnectTimeout(1000000);
        connection.setReadTimeout(1000000);

        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = xml.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        BufferedReader reader;
        String line;
        StringBuffer res = new StringBuffer();

        int status = connection.getResponseCode();
        if (status > 200) {
            reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            while ((line = reader.readLine()) != null) {
                res.append(line);
            }
            reader.close();
        } else {
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            while ((line = reader.readLine()) != null) {
                res.append(line);
            }
            reader.close();
        }
        Document document = convertStringToXMLDocument(res.toString());
        document.getDocumentElement().normalize();
        NodeList nList = document.getElementsByTagName("cybox:Observable");
        for (int n = 0; n < nList.getLength(); n++) {
            if (nList.item(n).hasChildNodes()) {
                Node node = nList.item(n);
                Element element = (Element) node;
                if (element.getElementsByTagName("cybox:Title").item(0) != null) {
                    Element e = (Element) element.getElementsByTagName("cybox:Object").item(0);
                    Element e1 = (Element) e.getElementsByTagName("cybox:Properties").item(0);
                    String s = e1.getAttribute("type");
                    String s1 = e1.getAttribute("xsi:type");
                    if (s.equals("URL")) {
                        String URL = e1.getElementsByTagName("URIObj:Value").item(0).getTextContent();
                        data.get("url").add(URL);
                    } else if (s1.equals("DomainNameObj:DomainNameObjectType")) {
                        Element e4 = (Element) e1.getElementsByTagName("DomainNameObj:Value").item(0);
                        String str1 = e4.getTextContent();
                        if (data.containsKey("Domain")) {
                            data.get("Domain").add(str1);
                        } else {
                            ArrayList<String> da = new ArrayList<String>();
                            da.add(str1);
                            data.put("Domain", da);
                        }

                    } else if (s1.equals("FileObj:FileObjectType")) {
                        Element e2 = (Element) e1.getElementsByTagName("FileObj:Hashes").item(0);
                        Element e3 = (Element) e2.getElementsByTagName("cyboxCommon:Hash").item(0);
                        String str = e3.getElementsByTagName("cyboxCommon:Simple_Hash_Value").item(0).getTextContent();
                        if (data.containsKey("Hashes")) {
                            data.get("Hashes").add(str);
                        } else {
                            ArrayList<String> da = new ArrayList<String>();
                            da.add(str);
                            data.put("Hashes", da);
                        }

                    } else {
                        if (data.containsKey("IP")) {
                            String IP = e1.getElementsByTagName("AddressObj:Address_Value").item(0).getTextContent();

                            data.get("IP").add(IP);
                        } else {
                            String IP = e1.getElementsByTagName("AddressObj:Address_Value").item(0).getTextContent();
                            ArrayList<String> da = new ArrayList<String>();
                            da.add(IP);
                            data.put("IP", da);
                        }
                    }

                }

            }

        }
    }

    void malwareDomain() throws IOException {
        HttpURLConnection connection;
        String xml = "<taxii_11:Poll_Request xmlns:taxii_11=\"http://taxii.mitre.org/messages/taxii_xml_binding-1.1\" message_id=\"42158\" collection_name=\"guest.MalwareDomainList_Hostlist\"><taxii_11:Exclusive_Begin_Timestamp>2017-01-19T00:00:00Z</taxii_11:Exclusive_Begin_Timestamp><taxii_11:Inclusive_End_Timestamp>2017-12-19T12:00:00Z</taxii_11:Inclusive_End_Timestamp><taxii_11:Poll_Parameters allow_asynch=\"false\"><taxii_11:Response_Type>FULL</taxii_11:Response_Type> </taxii_11:Poll_Parameters></taxii_11:Poll_Request>";
        URL url = new URL("http://hailataxii.com/taxii-discovery-service");
        connection = (HttpURLConnection) url.openConnection();

        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/xml");
        connection.setRequestProperty("Accept", "application/xml");
        connection.setRequestProperty("X-TAXII-Services", "urn:taxii.mitre.org:services:1.1");
        connection.setRequestProperty("X-TAXII-Protocol", "urn:taxii.mitre.org:protocol:http:1.0");
        connection.setRequestProperty("Proxy-Connection", "keep-alive");
        connection.setRequestProperty("Host", "taxiitest.mitre.org");
        connection.setRequestProperty("X-TAXII-Content-Type", "urn:taxii.mitre.org:message:xml:1.1");
        connection.setRequestProperty("X-TAXII-Accept", "urn:taxii.mitre.org:message:xml:1.1");
        connection.setRequestProperty("X-TAXII-Content-Types", "urn:taxii.mitre.org:message:xml:1.0");
        connection.setDoOutput(true);
        connection.setConnectTimeout(1000000);
        connection.setReadTimeout(1000000);

        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = xml.getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        BufferedReader reader;
        String line;
        StringBuffer res = new StringBuffer();

        int status = connection.getResponseCode();
        if (status > 200) {
            reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            while ((line = reader.readLine()) != null) {
                res.append(line);
            }
            reader.close();
        } else {
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            while ((line = reader.readLine()) != null) {
                res.append(line);
            }
            reader.close();
        }
        Document document = convertStringToXMLDocument(res.toString());
        document.getDocumentElement().normalize();
        NodeList nList = document.getElementsByTagName("cybox:Observable");
        for (int n = 0; n < nList.getLength(); n++) {
            if (nList.item(n).hasChildNodes()) {
                Node node = nList.item(n);
                Element element = (Element) node;
                if (element.getElementsByTagName("cybox:Title").item(0) != null) {
                    Element e = (Element) element.getElementsByTagName("cybox:Object").item(0);
                    Element e1 = (Element) e.getElementsByTagName("cybox:Properties").item(0);
                    String s = e1.getAttribute("type");
                    String s1 = e1.getAttribute("xsi:type");
                    String s3 = e1.getAttribute("category");
                    if (s.equals("URL")) {
                        Element element2 = (Element) element.getElementsByTagName("cybox:Object").item(0);
                        Element element3 = (Element) element2.getElementsByTagName("cybox:Properties").item(0);
                        String str = element3.getElementsByTagName("URIObj:Value").item(0).getTextContent();
                        data.get("url").add(str);
                    } else if (s1.equals("DomainNameObj:DomainNameObjectType")) {
                        Element e4 = (Element) e1.getElementsByTagName("DomainNameObj:Value").item(0);
                        String str1 = e4.getTextContent();
                        if (data.containsKey("Domain")) {
                            data.get("Domain").add(str1);
                        } else {
                            ArrayList<String> da = new ArrayList<String>();
                            da.add(str1);
                            data.put("Domain", da);
                        }

                    } else if (s3.equals("asn")) {
                        Element e4 = (Element) e1.getElementsByTagName("AddressObj:Address_Value").item(0);
                        String str1 = e4.getTextContent();
                        if (data.containsKey("ASN")) {
                            data.get("ASN").add(str1);
                        } else {
                            ArrayList<String> da = new ArrayList<String>();
                            da.add(str1);
                            data.put("ASN", da);
                        }
                    } else if (s1.equals("FileObj:FileObjectType")) {
                        Element e2 = (Element) e1.getElementsByTagName("FileObj:Hashes").item(0);
                        Element e3 = (Element) e2.getElementsByTagName("cyboxCommon:Hash").item(0);
                        String str = e3.getElementsByTagName("cyboxCommon:Simple_Hash_Value").item(0).getTextContent();
                        if (data.containsKey("Hashes")) {
                            data.get("Hashes").add(str);
                        } else {
                            ArrayList<String> da = new ArrayList<String>();
                            da.add(str);
                            data.put("Hashes", da);
                        }

                    } else {
                        if (data.containsKey("IP")) {
                            String IP = e1.getElementsByTagName("AddressObj:Address_Value").item(0).getTextContent();
                            data.get("IP").add(IP);
                        } else {
                            String IP = e1.getElementsByTagName("AddressObj:Address_Value").item(0).getTextContent();
                            ArrayList<String> da = new ArrayList<String>();
                            da.add(IP);
                            data.put("IP", da);
                        }
                    }

                }

            }

        }
    }

    private static Document convertStringToXMLDocument(String xmlString) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = null;
        try {
            builder = factory.newDocumentBuilder();

            Document doc = builder.parse(new InputSource(new StringReader(xmlString)));
            return doc;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    synchronized public void run() {
        System.out.println("worked");
        SomeDailyJob apIcall = new SomeDailyJob();
        try {
            apIcall.phishTank();
            apIcall.abuseCH();
            apIcall.malwareDomain();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        DB db = DBMaker.fileDB("_Windows____Firewall__logs.db").fileMmapEnable().fileLockWait().make();
        HTreeMap.KeySet<String> ipLogs = db.get("IP");
        HTreeMap.KeySet<String> hashes = db.get("Hashes");
        HTreeMap.KeySet<String> urls = db.get("url");
        HTreeMap.KeySet<String> domain = db.get("Domain");
        HTreeMap.KeySet<String> asn = db.get("ASN");
        if (ipLogs != null && ipLogs.size() > 0) {
            ipLogs.clear();
        }
        if (hashes != null && hashes.size() > 0) {
            hashes.clear();
        }
        if (urls != null && urls.size() > 0) {
            urls.clear();
        }
        if (domain != null && domain.size() > 0) {
            domain.clear();
        }
        if (asn != null && asn.size() > 0) {
            asn.clear();
        }
        Set<String> keys = data.keySet();
        for (String k : keys) {
            ArrayList<String> v = data.get(k);
            KeySet<String> map = db.hashSet(k).serializer(Serializer.STRING).createOrOpen();

            for (String val : v)
                map.add(val);

        }
        // Map<String, Object> str = db.getAll();

        // System.out.println(str);
        db.close();
        data.clear();
        File test = new File(System.getProperty("user.dir") + "/_Windows____Firewall__logs.db");
        System.out.println(test.exists());
        System.out.println("work done");
    }

}
