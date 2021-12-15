package com.shree;


import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.Serializer;



public class FileChangeDectector {
    public void test(){
        System.out.println("inside file change event");
       
        DB db = DBMaker.fileDB("MalisiousFirewall.db").fileMmapEnableIfSupported().fileLockWait()
        .make();
        List<String> dates = db.indexTreeList("dates", Serializer.STRING).createOrOpen(); 
        if(dates.size()==0){
            System.out.print("inside dates");
            db.close();
            LogFetch log = new LogFetch();
                   log.fetchLogs();
                   
        } 
        else{
            db.close();
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
                   LogFetch log = new LogFetch();
                   log.fetchLogs();
                 }
             }
        }while(watchKey.reset());
    } catch (Exception e) {

    }
}
}
