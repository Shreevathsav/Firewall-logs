package com.shree;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.List;
import java.util.regex.Pattern;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.HTreeMap;
import org.mapdb.Serializer;

import java.util.regex.Matcher;

public class LogFetch {
   public void fetchLogs(){
       System.out.println("inside fetch");
    DB db = DBMaker.fileDB("malisious.db").fileMmapEnableIfSupported().fileLockWait()
    .make();
    List<String> index = db.indexTreeList("SerialNo", Serializer.STRING).createOrOpen();
    List<String> f = db.indexTreeList("maliciousFlag", Serializer.STRING).createOrOpen();
    List<String> dates = db.indexTreeList("dates", Serializer.STRING).createOrOpen();
    List<String> time = db.indexTreeList("time", Serializer.STRING).createOrOpen();
    List<String> ipSource = db.indexTreeList("Source", Serializer.STRING).createOrOpen();
    List<String> ipDestination = db.indexTreeList("Destination", Serializer.STRING).createOrOpen();
    HTreeMap.KeySet<String> ipDBLogs = db.get("IP");

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
                    "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log.txt");

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
                System.out.println("Hi");
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
                    if (matcher4.matches() || matcher3.matches() || matcher5.matches()
                            || matcher6.matches()
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
        db.close();
   } 
}