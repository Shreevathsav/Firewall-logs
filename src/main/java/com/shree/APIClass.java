package com.shree;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.annotation.WebServlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.gson.Gson;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.Serializer;

@WebServlet("/FirewallLogs")

public class APIClass extends HttpServlet {
    synchronized public void service(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String currentPage = request.getParameter("currentPage");
        String rcrdsPerPage = request.getParameter("rcrdsPerPage");
        String firstCall = request.getParameter("firstCall");
        String filterType = request.getParameter("filterType");
        String filterValue = request.getParameter("filterValue");
        System.out.println(rcrdsPerPage);

        DB db = DBMaker.fileDB("MalisiousFirewallSSS.db").fileMmapEnableIfSupported().fileLockWait()
                .make();
        System.out.println("done initializing");
        List<String> streamFlag = db.indexTreeList("stream", Serializer.STRING).createOrOpen();
            System.out.println("size1 "+streamFlag.size());
        List<String> f = db.indexTreeList("maliciousFlag", Serializer.STRING).createOrOpen();
        List<String> dates = db.indexTreeList("dates", Serializer.STRING).createOrOpen();
        List<String> time = db.indexTreeList("time", Serializer.STRING).createOrOpen();
        List<String> ipSource = db.indexTreeList("Source", Serializer.STRING).createOrOpen();
        List<String> ipDestination = db.indexTreeList("Destination", Serializer.STRING).createOrOpen();
        HashMap<String, List<String>> firewallLogs = new HashMap<String, List<String>>();
        if (firstCall != null) {
            Map<Integer,String> asnMap = db.get("ASN");
            Map<Integer,String> ipMap = db.get("IP");
            Map<Integer,String> hashesMap = db.get("Hashes");
            Map<Integer,String> urlMap = db.get("url");
            Map<Integer,String> domainMap = db.get("Domain");
            List<String> asn = new ArrayList<String>();
            List<String> urls = new ArrayList<String>();
            List<String> domain  = new ArrayList<String>();
            List<String> hashes = new ArrayList<String>();
            List<String> ipLogs = new ArrayList<String>();
            for(int i : asnMap.keySet()){
                asn.add(asnMap.get(i));
            }
            for(int i : ipMap.keySet()){
                ipLogs.add(ipMap.get(i));
            }
            for(int i : urlMap.keySet()){
                urls.add(urlMap.get(i));
            }
            for(int i : domainMap.keySet()){
                domain.add(domainMap.get(i));
            }
            for(int i : hashesMap.keySet()){
                hashes.add(hashesMap.get(i));
            }


            firewallLogs.put("ASN", asn);
            firewallLogs.put("url", urls);
            firewallLogs.put("Domain", domain);
            firewallLogs.put("Hashes", hashes);
            firewallLogs.put("IP", ipLogs);
        } else {

            int rcrdPerPage = Integer.parseInt(rcrdsPerPage);
            String status = null;
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
                    status = "501";
                }
                System.out.println(status);
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (status.equals("200")) {
                Map<Integer,String> ipDBLogsMap = db.get("IP");
                ArrayList<String> ipDBLogs = new ArrayList<String>();
                for(int i : ipDBLogsMap.keySet()){
                ipDBLogs.add(ipDBLogsMap.get(i));
                }
                if (ipDBLogs.size()==0) {
                    ArrayList<String> stcode = new ArrayList<String>();
                    stcode.add("403");

                    firewallLogs.put("status", stcode);
                } else {
                    int start;
                    int end;
                    int tempstart = 0;
                    int tempend = ipSource.size();

                    if (filterType != null && filterType.equals("date")) {
                        if (dates.indexOf(filterValue) != -1) {
                            tempstart = dates.indexOf(filterValue);
                            tempend = dates.lastIndexOf(filterValue) + 1;
                        }
                        else{
                            tempstart=-1;
                        }
                    } 
                   
                    if(tempstart==-1){
                        List<String> statusCode = new ArrayList<String>();
                        statusCode.add("404");
                        firewallLogs.put("status", statusCode);
                    }
                    else{
                        System.out.println(tempstart);
                        List<String> tempDates = dates.subList(tempstart, tempend);
                        List<String> tempTime = time.subList(tempstart, tempend);
                        List<String> tempipSource = ipSource.subList(tempstart, tempend);
                        List<String> tempiDestination = ipDestination.subList(tempstart, tempend);
                        List<String> flag = f.subList(tempstart, tempend);
                        System.out.println(tempipSource.size());
                        System.out.println("curentPage "+currentPage);
                        int no_of_pages = tempipSource.size() / rcrdPerPage;
                        if (no_of_pages * rcrdPerPage < tempipSource.size()) {
                            no_of_pages = no_of_pages + 1;
                        }
                        if (tempDates.size() % rcrdPerPage == 0) {
    
                            start = (((no_of_pages - Integer.parseInt(currentPage)) + 1) * rcrdPerPage);
                            end = start - rcrdPerPage;
    
                        } else {
                            start = (((no_of_pages - Integer.parseInt(currentPage))) * rcrdPerPage
                                    + (tempDates.size() % rcrdPerPage));
                            end = start - rcrdPerPage;
                            if (end < 0) {
                                end = 0;
                            }
                        }
                        System.out.println("after start");
                        System.out.println(end + " " + start);
                        List<String> totalPages = new ArrayList<String>();
                        totalPages.add(Integer.toString(no_of_pages));
                        List<String> statusCode = new ArrayList<String>();
                        statusCode.add("200");
                        System.out.println("testing");
                        firewallLogs.put("totalPages", totalPages);
                        firewallLogs.put("status", statusCode);
                        firewallLogs.put("date", tempDates.subList(end, start));
                        firewallLogs.put("time", tempTime.subList(end, start));
                        firewallLogs.put("IPSrc", tempipSource.subList(end, start));
                        firewallLogs.put("IPDest", tempiDestination.subList(end, start));
                        firewallLogs.put("FLAG", flag.subList(end, start));
    
                    }
                   
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
        }

        Gson gson = new Gson();

        String jsonLogs = gson.toJson(firewallLogs);
        System.out.println("done2");
        PrintWriter printWriter = response.getWriter();
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        System.out.println("done2");
        printWriter.write(jsonLogs);
        System.out.println("done2");
        db.close();
        printWriter.flush();
        printWriter.close();

    }

    int getNoOfPages(List<String> ipSource, int rcrdPerPage) {
        int no_of_pages = ipSource.size() / rcrdPerPage;
        if (no_of_pages * rcrdPerPage < ipSource.size()) {
            no_of_pages = no_of_pages + 1;
        }
        return no_of_pages;
    }

    List<Integer> getStartEndOfPagination(List<String> ipSource, int rcrdPerPage, int no_of_pages, String currentPage) {
        List<Integer> startEnd = new ArrayList<Integer>();
        int start;
        int end;
        if (ipSource.size() % rcrdPerPage == 0) {

            start = (((no_of_pages - Integer.parseInt(currentPage)) + 1) * rcrdPerPage);
            end = start - rcrdPerPage;

        } else {
            start = (((no_of_pages - Integer.parseInt(currentPage))) * rcrdPerPage
                    + (ipSource.size() % rcrdPerPage));
            end = start - rcrdPerPage;
            if (end < 0) {
                end = 0;
            }
        }
        startEnd.add(start);
        startEnd.add(end);
        return startEnd;
    }
}
