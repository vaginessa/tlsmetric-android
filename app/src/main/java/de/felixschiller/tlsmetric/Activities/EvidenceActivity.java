package de.felixschiller.tlsmetric.Activities;

import android.app.ListActivity;
import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;

import java.util.ArrayList;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.Assistant.ContextSingleton;
import de.felixschiller.tlsmetric.PacketAnalyze.Announcement;
import de.felixschiller.tlsmetric.PacketAnalyze.Evidence;
import de.felixschiller.tlsmetric.PacketAnalyze.PackageInformation;
import de.felixschiller.tlsmetric.R;

public class EvidenceActivity extends ListActivity {


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_evidence);
        ContextSingleton.setContext(this);


        final ListView listview = (ListView) findViewById(android.R.id.list);


        final EvidenceAdapter adapter;
        if(Evidence.mEvidenceDetail != null){
             adapter = new EvidenceAdapter(this, Evidence.mEvidence);
        } else {
            if(Const.IS_DEBUG) Log.e(Const.LOG_TAG, "Evidence list not existing or empty!");
            adapter = new EvidenceAdapter(this, new ArrayList<Announcement>());
        }


        listview.setAdapter(adapter);

        listview.setOnItemClickListener(new AdapterView.OnItemClickListener() {

            //TODO: Open detail Page on Click
            @Override
            public void onItemClick(AdapterView<?> parent, final View view,
                                    int position, long id) {
                final Announcement item = (Announcement) parent.getItemAtPosition(position);
                view.animate().setDuration(2000).alpha(0)
                        .withEndAction(new Runnable() {
                            @Override
                            public void run() {
                                //filterList.remove(item);
                                adapter.notifyDataSetChanged();
                                view.setAlpha(1);
                            }
                        });
            }

        });

        //TODO: UpdateLoopForAdapter
    }


    private class EvidenceAdapter extends ArrayAdapter<Announcement> {

        private final Announcement[] anns;
        private final Context context;

        public EvidenceAdapter(Context context, ArrayList<Announcement> AnnList) {
            super(context, R.layout.evidence_list_entry, AnnList);
            this.context = context;
            this.anns = new Announcement[AnnList.size()];
            for(int i = 0; i < AnnList.size(); i++){
                this.anns[i] = AnnList.get(i);
            }
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            LayoutInflater inflater = (LayoutInflater) context
                    .getSystemService(Context.LAYOUT_INFLATER_SERVICE);

            View rowView = inflater.inflate(R.layout.evidence_list_entry, parent, false);

            PackageInformation pi = Evidence.getPackageInformation(anns[position].srcPort);

            //First Line Text
            TextView firstLine = (TextView) rowView.findViewById(R.id.firstLine);
            String first = pi.packageName;
            firstLine.setText(first);

            //second Line Text
            TextView secondLine = (TextView) rowView.findViewById(R.id.secondLine);
            String second = "Connection to: " + anns[position].url;
            secondLine.setText(second);

            //App icon
            ImageView imageView = (ImageView) rowView.findViewById(R.id.icon);
            imageView.setImageDrawable(pi.icon);

            //Status icon
            ImageView imageStatusView = (ImageView) rowView.findViewById(R.id.statusIcon);
            int severity = anns[position].filter.severity;
            if(severity == 3){
                imageStatusView.setImageResource(R.drawable.icon_warn_036);
                imageStatusView.setBackgroundColor(Color.RED);
            } else if (severity == 2){
                imageStatusView.setImageResource(R.drawable.icon_warn_036);
                imageStatusView.setBackgroundColor(Color.YELLOW);
            } else if (severity == 1) {
                imageStatusView.setImageResource(R.drawable.icon_warn_036);
                imageStatusView.setBackgroundColor(Color.YELLOW);
            } else {
                imageStatusView.setImageResource(R.drawable.icon_ok_036);
                imageStatusView.setBackgroundColor(Color.YELLOW);
            }

            //Status Text
            TextView statusLine = (TextView) rowView.findViewById(R.id.statusLine);
            String status = "Level :" + severity;
            statusLine.setText(status);
            return rowView;
        }

    }

    @Override
    public void onDestroy(){
        //kill the singleton
        ContextSingleton.setContext(null);
        super.onDestroy();
    }


}