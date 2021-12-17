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
        System.out.println("inside live geed");
        PrintWriter printWriter = null;
            String status = null;
            SingletonClass sc = SingletonClass.getInstance();
            printWriter = response.getWriter();
                for(int i=0;i<sc.datesList.size();i++){
                    printWriter.write("event: message\n");
                    printWriter.write("data:" + "{\"date\": \""+sc.datesList.get(0) + "\", \n");
                    System.out.println(sc.datesList.size());
                    printWriter.write("data:" + "\"time\": \""+sc.timeList.get(0) + "\", \n");
                    printWriter.write("data:" + "\"ipsource\": \""+sc.sourceList.get(0) + "\", \n");
                    printWriter.write("data:" + "\"ipdestination\": \""+sc.destinationList.get(0) + "\", \n");
                    printWriter.write("data:" + "\"flag\": \""+sc.flagList.get(0) + "\"} \n\n");
                    response.flushBuffer();
                }
                // sc.datesList.clear();
                // sc.destinationList.clear();
                // sc.flagList.clear();
                // sc.sourceList.clear();
                // sc.timeList.clear();

            
           
            
                }
    
}
