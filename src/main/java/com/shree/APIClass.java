package com.shree;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;

import java.util.HashMap;
import java.util.List;


import javax.servlet.annotation.WebServlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.gson.Gson;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.HTreeMap;
import org.mapdb.Serializer;

@WebServlet("/FirewallLogs")

public class APIClass extends HttpServlet {
    @SuppressWarnings("unchecked")
    synchronized public void service(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String currentPage = request.getParameter("currentPage");
        String rcrdsPerPage = request.getParameter("rcrdsPerPage");
        String firstCall = request.getParameter("firstCall");
        System.out.println(rcrdsPerPage);

        DB db = DBMaker.fileDB("MalisiousFirewall.db").fileMmapEnableIfSupported().fileLockWait()
                .make();
            System.out.println("done initializing");
        List<String> f = db.indexTreeList("maliciousFlag", Serializer.STRING).createOrOpen();
        List<String> dates = db.indexTreeList("dates", Serializer.STRING).createOrOpen();
        List<String> time = db.indexTreeList("time", Serializer.STRING).createOrOpen();
        List<String> ipSource = db.indexTreeList("Source", Serializer.STRING).createOrOpen();
        List<String> ipDestination = db.indexTreeList("Destination", Serializer.STRING).createOrOpen();
        HashMap<String, List<String>> firewallLogs = new HashMap<String, List<String>>();
        if (firstCall != null) {
            List<String> asn = (List<String>) (Object) Arrays.asList(db.get("ASN"));
            List<String> ipLogs = (List<String>) (Object) Arrays.asList(db.get("IP"));
            List<String> hashes = (List<String>) (Object) Arrays.asList(db.get("Hashes"));
            List<String> urls = (List<String>) (Object) Arrays.asList(db.get("url"));
            List<String> domain = (List<String>) (Object) Arrays.asList(db.get("Domain"));

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
                    status = "500";
                }
                System.out.println(status);
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (status.equals("200")) {
                HTreeMap.KeySet<String> ipDBLogs = db.get("IP");
                if (ipDBLogs == null) {
                    ArrayList<String> stcode = new ArrayList<String>();
                    stcode.add("403");

                    firewallLogs.put("status", stcode);
                } else {
                        
                        int no_of_pages = ipSource.size() / rcrdPerPage;
                        if (no_of_pages * rcrdPerPage < ipSource.size()) {
                            no_of_pages = no_of_pages + 1;
                        }
                        System.out.println("after no_of pags");
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

                    System.out.println("after start");
                        List<String> totalPages = new ArrayList<String>();
                        totalPages.add(Integer.toString(no_of_pages));
                        List<String> statusCode = new ArrayList<String>();
                        statusCode.add("200");
                        System.out.println("testing");
                        firewallLogs.put("totalPages", totalPages);
                        firewallLogs.put("status", statusCode);
                        firewallLogs.put("date", dates.subList(end, start));
                        firewallLogs.put("time", time.subList(end, start));
                        firewallLogs.put("IPSrc", ipSource.subList(end, start));
                        firewallLogs.put("IPDest", ipDestination.subList(end, start));
                        firewallLogs.put("FLAG", f.subList(end, start));

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
