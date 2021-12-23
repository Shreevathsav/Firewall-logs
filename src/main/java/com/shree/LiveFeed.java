package com.shree;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.gson.Gson;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.HTreeMap;
import org.mapdb.Serializer;
import org.mapdb.serializer.SerializerArray;

@WebServlet("/LiveFeed")

public class LiveFeed extends HttpServlet{
    public void service(HttpServletRequest request,HttpServletResponse response) throws IOException{
        response.setContentType("text/event-stream");
        response.setCharacterEncoding("UTF-8");
        PrintWriter printWriter = null;
            String status = null;
            DB db = DBMaker.fileDB("MalisiousFirewallnine.db").fileMmapEnableIfSupported().fileLockWait()
            .make();
            List<String> f = db.indexTreeList("maliciousFlag", SerializerArray.STRING).createOrOpen();
            List<String> dates = db.indexTreeList("dates", Serializer.STRING).createOrOpen();
            List<String> time = db.indexTreeList("time", Serializer.STRING).createOrOpen();
            List<String> ipSource = db.indexTreeList("Source", Serializer.STRING).createOrOpen();
            List<String> ipDestination = db.indexTreeList("Destination", Serializer.STRING).createOrOpen();
            List<String> streamFlag = db.indexTreeList("stream", Serializer.STRING).createOrOpen();
            System.out.println("size1 "+streamFlag.size());
            System.out.println("size1 "+ipSource.size());
            HashMap<String, List<String>> firewallLogs = new HashMap<String, List<String>>();
            File file = new File("C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log.txt");
            try {
                String command = "reg query \"HKU\\S-1-5-19\"";
                Process p = Runtime.getRuntime().exec(command);
                p.waitFor();
                int exitValue = p.exitValue();
                System.out.println(file.exists());
                if (0 == exitValue && file.exists()) {
                    status = "200";
                } else if (exitValue != 0 && !(file.exists())) {
                    status = "400";
                } else if (exitValue != 0) {
                    status = "401";
                }

                else if (!(file.exists())) {
                    status = "402";
                } else {
                    status = "500";
                }
                System.out.println(status);
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (status.equals("200")) {
                System.out.println("size" + streamFlag.size());

                HTreeMap.KeySet<String> ipDBLogs = db.get("IP");
                if (ipDBLogs == null) {
                    ArrayList<String> stcode = new ArrayList<String>();
                    stcode.add("403");

                    firewallLogs.put("status", stcode);
                } else if(streamFlag.size()>0){
                    streamFlag.clear();
                    int start = ipSource.size();
                    int end = start-100;
                    if(end<0){
                        end=0;
                    }
                        System.out.println("after no_of pags");
                        System.out.println("after start");
                        List<String> statusCode = new ArrayList<String>();
                        statusCode.add("200");
                        System.out.println("testing");
                        firewallLogs.put("status", statusCode);
                        firewallLogs.put("date", dates.subList(end, start));
                        firewallLogs.put("time", time.subList(end, start));
                        firewallLogs.put("IPSrc", ipSource.subList(end, start));
                        firewallLogs.put("IPDest", ipDestination.subList(end, start));
                        firewallLogs.put("FLAG", f.subList(end, start));

                    }
                    else{
                        List<String> statusCode = new ArrayList<String>();
                        statusCode.add("500");
                        firewallLogs.put("status", statusCode);
                    }



            } else {
                ArrayList<String> stcode = new ArrayList<String>();
                if (status.equals("400")) {
                    stcode.add("400");
                } else if (status.equals("401")) {
                    stcode.add("401");
                } else if (status.equals("402")) {
                    stcode.add("402");
                } else {
                    stcode.add("403");
                }

                firewallLogs.put("status", stcode);

            }
            Gson gson = new Gson();

        String jsonLogs = gson.toJson(firewallLogs);
       
        db.close();
        System.out.println("done2");
        printWriter = response.getWriter();
        System.out.println("done2");
        printWriter.write("event: message\n");
        printWriter.write("data:" + jsonLogs + "\n\n");
        response.flushBuffer();
        System.out.println("done2");


        }

}