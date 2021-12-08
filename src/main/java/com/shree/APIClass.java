package com.shree;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;

import java.util.HashMap;
import java.util.List;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
        int rcrdPerPage = Integer.parseInt(rcrdsPerPage);
        DB db = DBMaker.fileDB("LOG.db").fileMmapEnableIfSupported().fileLockWait()
                .make();
        List<String> index = db.indexTreeList("SerialNo", Serializer.STRING).createOrOpen();
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

        }

        String status = null;
        File file = new File("C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log");
        try {
            String command = "reg query \"HKU\\S-1-5-19\"";
            Process p = Runtime.getRuntime().exec(command);
            p.waitFor();
            int exitValue = p.exitValue();

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

                if (currentPage.equals("1")) {
                    String zeroTo255 = "(\\d{1,2}|(0|1)\\" + "d{2}|2[0-4]\\d|25[0-5])";
                    String IPV4_REGEX = zeroTo255 + "\\." + zeroTo255 + "\\." + zeroTo255 + "\\." + zeroTo255;

                    String IPV6_HEX4DECCOMPRESSED_REGEX = "\\A((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?) ::((?:[0-9A-Fa-f]{1,4}:)*)(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}\\z";
                    String IPV6_6HEX4DEC_REGEX = "\\A((?:[0-9A-Fa-f]{1,4}:){6,6})(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}\\z";
                    String IPV6_HEXCOMPRESSED_REGEX = "\\A((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)\\z";
                    String IPV6_REGEX = "\\A(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\\z";

                    String dateRegex = "(?m)^(?:[0-9]{2})?[0-9]{2}-[0-3]?[0-9]-[0-3]?[0-9]$";
                    String timeRegex = "^([2][0-3]|[0-1][0-9]|[1-9]):[0-5][0-9]:([0-5][0-9]|[6][0])";
                    try {
                        FileInputStream fstream = new FileInputStream(
                                "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log");

                        BufferedReader br = new BufferedReader(new InputStreamReader(fstream));
                        int skip;

                        List<String> tempLines = br.lines().toList();
                        System.out.println(tempLines.size() - 5);
                        System.out.println(index.size());
                        if ((tempLines.size() - 5) < index.size()) {
                            skip = 0;
                            index.clear();
                        } else {
                            skip = 5 + index.size();
                        }
                        System.out.println("skip " + skip);
                        br.close();
                        List<String> str = tempLines.subList(skip, tempLines.size());
                        System.out.println(str.size());
                        for (String strLine : str) {
                            int flag = 1;
                            String[] splited = strLine.split("\\s+");
                            Pattern ipv4Pattern = Pattern.compile(IPV4_REGEX);
                            Pattern ipv6Pattern1 = Pattern.compile(IPV6_REGEX);
                            Pattern ipv6Pattern2 = Pattern.compile(IPV6_6HEX4DEC_REGEX);
                            Pattern ipv6Pattern3 = Pattern.compile(IPV6_HEX4DECCOMPRESSED_REGEX);
                            Pattern ipv6Pattern4 = Pattern.compile(IPV6_HEXCOMPRESSED_REGEX);
                            Pattern datePattern = Pattern.compile(dateRegex);
                            Pattern timePattern = Pattern.compile(timeRegex);
                            String tempDate = null;
                            String tempTime = null;
                            int i = 0;
                            for (String s : splited) {

                                Matcher matcher1 = datePattern.matcher(s);
                                if (matcher1.matches()) {

                                    tempDate = s;
                                    dates.add(tempDate);

                                }
                                Matcher matcher2 = timePattern.matcher(s);
                                if (matcher2.matches()) {
                                    tempTime = s;
                                    time.add(tempTime);
                                } else {
                                }
                                Matcher matcher3 = ipv4Pattern.matcher(s);
                                Matcher matcher4 = ipv6Pattern1.matcher(s);
                                Matcher matcher5 = ipv6Pattern2.matcher(s);
                                Matcher matcher6 = ipv6Pattern3.matcher(s);
                                Matcher matcher10 = ipv6Pattern4.matcher(s);
                                if (matcher4.matches() || matcher3.matches() || matcher5.matches() || matcher6.matches()
                                        || matcher10.matches()) {

                                    if (flag == 1) {
                                        ipSource.add(s);

                                        flag = 0;
                                    } else if (flag == 0) {
                                        ipDestination.add(s);
                                        flag = 1;
                                    }
                                } else {
                                    // System.out.println("E");
                                }
                            }
                            if (ipDBLogs.contains(ipSource.get(i)) || ipDBLogs.contains(ipDestination.get(i))) {
                                f.add("1");
                            } else {
                                f.add("0");
                            }
                            i = i + 1;
                            index.add(Integer.toString(i));

                        }
                        fstream.close();
                    } catch (Exception e) {
                        System.err.println("Error: " + e.getMessage());
                    }
                    System.out.println("done adding flags");
                    int no_of_pages = getNoOfPages(ipSource, rcrdPerPage);
                    List<Integer> startEnd = getStartEndOfPagination(ipSource, rcrdPerPage, no_of_pages, currentPage);
                    int start = startEnd.get(0);
                    int end = startEnd.get(1);
                    List<String> flag = new ArrayList<String>(f);
                    List<String> totalPages = new ArrayList<String>();
                    totalPages.add(Integer.toString(no_of_pages));
                    List<String> statusCode = new ArrayList<String>();
                    statusCode.add("200");
                    firewallLogs.put("totalPages", totalPages);
                    firewallLogs.put("status", statusCode);
                    firewallLogs.put("date", dates.subList(end, start));
                    firewallLogs.put("time", time.subList(end, start));
                    firewallLogs.put("IPSrc", ipSource.subList(end, start));
                    firewallLogs.put("IPDest", ipDestination.subList(end, start));
                    firewallLogs.put("FLAG", flag.subList(end, start));

                } else {
                    int no_of_pages = getNoOfPages(ipSource, rcrdPerPage);
                    List<Integer> startEnd = getStartEndOfPagination(ipSource, rcrdPerPage, no_of_pages, currentPage);
                    int start = startEnd.get(0);
                    int end = startEnd.get(1);

                    List<String> flag = new ArrayList<String>(f);
                    List<String> totalPages = new ArrayList<String>();
                    totalPages.add(Integer.toString(no_of_pages));
                    List<String> statusCode = new ArrayList<String>();
                    statusCode.add("200");
                    firewallLogs.put("totalPages", totalPages);
                    firewallLogs.put("status", statusCode);
                    firewallLogs.put("date", dates.subList(end, start));
                    firewallLogs.put("time", time.subList(end, start));
                    firewallLogs.put("IPSrc", ipSource.subList(end, start));
                    firewallLogs.put("IPDest", ipDestination.subList(end, start));
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
