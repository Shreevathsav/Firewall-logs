package com.shree;


import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.Serializer;



public class FileChangeDectector {
    public void test() throws IOException{
        System.out.println("inside file change event");
       
        DB db = DBMaker.fileDB("FirewallLogProcessing.db").fileChannelEnable().fileLockDisable().checksumHeaderBypass()
    .make();
    System.out.println("after db");
    List<String> index = db.indexTreeList("SerialNo", Serializer.STRING).createOrOpen();
    List<String> f = db.indexTreeList("maliciousFlag", Serializer.STRING).createOrOpen();
    List<String> dates = db.indexTreeList("dates", Serializer.STRING).createOrOpen();
    List<String> time = db.indexTreeList("time", Serializer.STRING).createOrOpen();
    List<String> ipSource = db.indexTreeList("Source", Serializer.STRING).createOrOpen();
    List<String> ipDestination = db.indexTreeList("Destination", Serializer.STRING).createOrOpen();
    List<String> streamFlag = db.indexTreeList("stream", Serializer.STRING).createOrOpen();
    Map<Integer,String> ipDBLogsMap = db.get("IP");
    ArrayList<String> ipDBLogs = new ArrayList<String>();
    for(int i : ipDBLogsMap.keySet()){
        ipDBLogs.add(ipDBLogsMap.get(i));
    }
        FileInputStream fstream = new FileInputStream(
                    "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log.txt");

            BufferedReader br = new BufferedReader(new InputStreamReader(fstream));

            List<String> tempLines = br.lines().toList();
            System.out.println(tempLines.size());
            System.out.println(index.size());
            br.close();
        if(dates.size()==0 && index.size()<(tempLines.size()-5)){
            System.out.print("inside dates");
            streamFlag.add("added");
           
            LogFetch log = LogFetch.getInstance();
                   log.fetchLogs(f,index,dates,time,ipSource,ipDestination,ipDBLogs);
                   
        } 
        else if(index.size()>(tempLines.size()-5)){
            index.clear();
            
        }
             
    try(WatchService service = FileSystems.getDefault().newWatchService()) {
        Map<WatchKey, Path> keyMap = new HashMap<>();
        Path path = Paths.get("C:\\Windows\\System32\\LogFiles\\Firewall");
        keyMap.put(path.register(service,StandardWatchEventKinds.ENTRY_CREATE,StandardWatchEventKinds.ENTRY_DELETE,StandardWatchEventKinds.ENTRY_MODIFY),path);
        WatchKey watchKey;
        do{
            watchKey=service.take();
             for(WatchEvent<?> event:watchKey.pollEvents()){
                 WatchEvent.Kind<?> kind = event.kind();
                 Path eventPath = (Path)event.context();
                 System.out.println(kind+" "+eventPath.toString());
                 if(eventPath.toString().equals("pfirewall.log.txt")){
                    streamFlag.add("added");
                   LogFetch log = LogFetch.getInstance();
                   log.fetchLogs(f,index,dates,time,ipSource,ipDestination,ipDBLogs);
                 }
             }
        }while(watchKey.reset());
    } catch (Exception e) {

    }
    finally {
            
        db.close();
        
    }
}
}
