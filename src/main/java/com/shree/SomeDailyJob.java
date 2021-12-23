package com.shree;

import java.io.IOException;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Date;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.HTreeMap;
import org.mapdb.IndexTreeList;
import org.mapdb.Serializer;
import org.mapdb.HTreeMap.KeySet;
import org.mapdb.serializer.SerializerArray;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class SomeDailyJob implements Runnable {
    static HashMap<String, ArrayList<String>> data = new HashMap<String, ArrayList<String>>();

    void phishTank() throws IOException {
        System.out.println("inside ch");
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

        System.out.println("headers");

        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = xml.getBytes("utf-8");
            os.write(input, 0, input.length);
        }
        System.out.println("outputstream");
        BufferedReader reader;
        String line;
        StringBuffer res = new StringBuffer();

        int status = connection.getResponseCode();
        if (status == 200) {
            System.out.println("if");
            ArrayList<String> stsCode = new ArrayList<String>();
            stsCode.add("200");
            data.put("Status3", stsCode);
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            while ((line = reader.readLine()) != null) {
                res.append(line);
            }
            System.out.println("while");
            reader.close();
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
            System.out.println("for");
        } else {
            ArrayList<String> stsCode = new ArrayList<String>();
            stsCode.add("400");
            data.put("Status3", stsCode);
        }
        System.out.println("done fetcing malware-Stix");
    }

    void abuseCH() throws IOException {
        System.out.println("inside ch");
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
        if (status == 200) {
            System.out.print("if");
            ArrayList<String> stsCode = new ArrayList<String>();
            stsCode.add("200");
            data.put("Status2", stsCode);
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            while ((line = reader.readLine()) != null) {
                res.append(line);
            }
            reader.close();
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
                            String str = e3.getElementsByTagName("cyboxCommon:Simple_Hash_Value").item(0)
                                    .getTextContent();
                            if (data.containsKey("Hashes")) {
                                data.get("Hashes").add(str);
                            } else {
                                ArrayList<String> da = new ArrayList<String>();
                                da.add(str);
                                data.put("Hashes", da);
                            }

                        } else {
                            if (data.containsKey("IP")) {
                                String IP = e1.getElementsByTagName("AddressObj:Address_Value").item(0)
                                        .getTextContent();

                                data.get("IP").add(IP);
                            } else {
                                String IP = e1.getElementsByTagName("AddressObj:Address_Value").item(0)
                                        .getTextContent();
                                ArrayList<String> da = new ArrayList<String>();
                                da.add(IP);
                                data.put("IP", da);
                            }
                        }

                    }

                }

            }
        } else {
            ArrayList<String> stsCode = new ArrayList<String>();
            stsCode.add("400");
            data.put("Status2", stsCode);
        }
        System.out.println("done fetcing malware-Stix");
    }

    void malwareDomain() throws IOException {
        System.out.println("inside ch");
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
        if (status == 200) {
            ArrayList<String> stsCode = new ArrayList<String>();
            stsCode.add("200");
            data.put("Status1", stsCode);
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            while ((line = reader.readLine()) != null) {
                res.append(line);
            }
            reader.close();
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
                            String str = e3.getElementsByTagName("cyboxCommon:Simple_Hash_Value").item(0)
                                    .getTextContent();
                            if (data.containsKey("Hashes")) {
                                data.get("Hashes").add(str);
                            } else {
                                ArrayList<String> da = new ArrayList<String>();
                                da.add(str);
                                data.put("Hashes", da);
                            }

                        } else {
                            if (data.containsKey("IP")) {
                                String IP = e1.getElementsByTagName("AddressObj:Address_Value").item(0)
                                        .getTextContent();
                                data.get("IP").add(IP);
                            } else {
                                String IP = e1.getElementsByTagName("AddressObj:Address_Value").item(0)
                                        .getTextContent();
                                ArrayList<String> da = new ArrayList<String>();
                                da.add(IP);
                                data.put("IP", da);
                            }
                        }

                    }

                }

            }
        } else {
            ArrayList<String> stsCode = new ArrayList<String>();
            stsCode.add("400");
            data.put("Status1", stsCode);
        }
        System.out.println("done fetcing malware-Stix");

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
        System.out.println("hi");
        DB db = DBMaker.fileDB("MalisiousFirewallnine.db").fileMmapEnable().fileLockWait().make();
        IndexTreeList<Date> oldTime = db.indexTreeList("syncTime", Serializer.DATE).createOrOpen();
        long diff;
        if (oldTime != null && oldTime.size() > 0) {
            Map<String, Object> test = db.getAll();
            System.out.println(test);
            Date oldDate = oldTime.get(0);
            Date newDate = new Date();
            long diffInMillies = Math.abs(newDate.getTime() - oldDate.getTime());
            diff = TimeUnit.DAYS.convert(diffInMillies, TimeUnit.MILLISECONDS);
            System.out.println("difference" + diff);
        } else {
            diff = 1;
            System.out.println("hi" + diff);
        }
        if (diff >= 1) {
            if (oldTime.size() > 0) {
                oldTime.clear();
            }
            System.out.println("worked");
            SomeDailyJob apIcall = new SomeDailyJob();
            try {
                apIcall.phishTank();
                apIcall.abuseCH();
                apIcall.malwareDomain();
                System.out.println("done fetcing Stix");
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println("initializing db");

            System.out.println("created db");
            Set<String> keys = data.keySet();
            System.out.println("done getting");
            if (data.get("Status1").get(0) == "200" || data.get("Status2").get(0) == "200"
                    || data.get("Status3").get(0) == "200") {
                System.out.println("done if");

                // if (ipLogs != null && ipLogs.size() > 0 && data.containsKey("IP")) {
                //     ipLogs.clear();
                // }
                // if (hashes != null && hashes.size() > 0 && data.containsKey("Hashes")) {
                //     hashes.clear();
                // }
                // if (urls != null && urls.size() > 0 && data.containsKey("url")) {
                //     urls.clear();
                // }
                // if (domain != null && domain.size() > 0 && data.containsKey("Domain")) {
                //     domain.clear();
                // }
                // if (asn != null && asn.size() > 0 && data.containsKey("ASN")) {
                //     asn.clear();
                // }

                System.out.println("done clearing");

                for (String k : keys) {
                    ArrayList<String> v = data.get(k);
                    HTreeMap<String, String> map = db.hashMap(k).expireAfterCreate(1, TimeUnit.DAYS).keySerializer(Serializer.STRING).valueSerializer(Serializer.STRING)
                            .createOrOpen();
                    

                    for (String val : v)
                        map.put(k,val);

                }
                System.out.println("done adding them to db");
                Map<String, Object> test = db.getAll();
                System.out.println(test);

                Date now = new Date();
                IndexTreeList<Date> newTime = db.indexTreeList("syncTime", Serializer.DATE).createOrOpen();
                newTime.add(now);

            }

            if (data.size() > 0) {
                data.clear();
            }
            System.out.println("work done");

        }
        // KeySet<String> test1 =
        // db.hashMap("test").expireAfterCreate(1,TimeUnit.SECONDS).expireAfterUpdate(1,TimeUnit.SECONDS).keySerializer(Serializer.STRING).createOrOpen();
        // ScheduledExecutorService executor =
        // Executors.newScheduledThreadPool(2);
        // KeySet<String> test = db.hashSet("testing2")
        // .expireAfterCreate()
        // .expireAfterGet(1, TimeUnit.SECONDS).expireExecutor(executor)
        // .expireExecutorPeriod(1000).serializer(Serializer.STRING).createOrOpen();
        // test.add("test5");
        // KeySet<String> temp = db.get("testing");
        // System.out.println(test);
        // try {
        // Thread.sleep(3000);
        // } catch (InterruptedException e1) {
        // // TODO Auto-generated catch block
        // e1.printStackTrace();
        // }
        // System.out.println(test);
        // test.add("test2");
        // System.out.println(test);
        // HTreeMap cache = db
        //         .hashMap("test3")
        //         .expireAfterCreate(1, TimeUnit.SECONDS)
        //         .createOrOpen();

        // cache.put("hii", "hello1");

        // try {
        //     Thread.sleep(3000);
        // } catch (InterruptedException e1) {
        //     // TODO Auto-generated catch block
        //     e1.printStackTrace();
        // }
        // System.out.println(cache.get("hii"));
        // cache.put("hi", "hello2");
        // System.out.println(cache.get("hi"));
        // System.out.println(cache.get("hii"));

        db.close();
        System.out.println("db closed");
        System.out.println("check");

        FileChangeDectector f = new FileChangeDectector();
        try {
            f.test();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

}
