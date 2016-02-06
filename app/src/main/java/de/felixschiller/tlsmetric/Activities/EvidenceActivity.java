package de.felixschiller.tlsmetric.Activities;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.Assistant.ContextSingleton;
import de.felixschiller.tlsmetric.PacketAnalyze.Announcement;
import de.felixschiller.tlsmetric.PacketAnalyze.Evidence;
import de.felixschiller.tlsmetric.PacketAnalyze.PackageInformation;
import de.felixschiller.tlsmetric.R;

public class EvidenceActivity extends AppCompatActivity{


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_evidence);
        ContextSingleton.setContext(this);
        Evidence.newWarnings = 0;

        //Toolbar
        Toolbar toolbar = (Toolbar) findViewById(R.id.evidence_toolbar);
        setSupportActionBar(toolbar);
        //toolbar.setLogo(R.mipmap.icon);
        toolbar.setLogoDescription(R.string.app_name);


        //EvidenceList
        final ListView listview = (ListView) findViewById(android.R.id.list);

        final EvidenceAdapter adapter;
        if(Evidence.mEvidence != null){
            adapter = new EvidenceAdapter(this, copyArrayList(Evidence.getSortedEvidence()));
        } else {
            if(Const.IS_DEBUG) Log.e(Const.LOG_TAG, "Evidence list not existing or empty!");
            adapter = new EvidenceAdapter(this, new ArrayList<Announcement>());
        }

        listview.setAdapter(adapter);

        listview.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, final View view,
                                    int position, long id) {
                final Announcement ann = (Announcement) parent.getItemAtPosition(position);
                view.animate().setDuration(500).alpha((float)0.5)
                        .withEndAction(new Runnable() {
                            @Override
                            public void run() {
                                if (ann.filter.severity != -1) {
                                    Evidence.setSortedEvidenceDetail(ann.srcPort);
                                    Intent intent = new Intent(ContextSingleton.getContext(), EvidenceDetailActivity.class);
                                    startActivity(intent);
                                } else {
                                    Toast toast = Toast.makeText(ContextSingleton.getContext(), "No detail availiable for this connection", Toast.LENGTH_LONG);
                                    toast.show();
                                }
                            }
                        });
            }

        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.menu_tlsmetric, menu);
        return true;
    }

    //menu
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.action_settings:
                return true;

            case R.id.action_back:
                Intent intent = new Intent(ContextSingleton.getContext(), MainActivity.class);
                startActivity(intent);
                return true;

            case R.id.action_refresh:
                Evidence.disposeInactiveEvidence();
                Evidence.updateConnections();
                ListView listview = (ListView) findViewById(android.R.id.list);
                EvidenceAdapter adapter = new EvidenceAdapter(ContextSingleton.getContext(),
                        copyArrayList(Evidence.getSortedEvidence()));
                listview.setAdapter(adapter);
                adapter.notifyDataSetChanged();
                return true;

            default:
                return super.onOptionsItemSelected(item);
        }
    }

    private class EvidenceAdapter extends ArrayAdapter<Announcement> {

        private Announcement[] anns;
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

            //if unknown app (-1) try again to get pid by sourcePort;
            Announcement ann = anns[position];
            if(ann.pid == -1 && ann.uid == -1){
                ann.pid = Evidence.getPidByPort(ann.srcPort);
                ann.uid = Evidence.getUidByPort(ann.srcPort);
                if(Const.IS_DEBUG)Log.d(Const.LOG_TAG, "Rescan of pid and uid. srcPort: " +
                        ann.srcPort + " new pid: " + ann.pid
                        + " new uid: " + ann.uid);
            }

            PackageInformation pi = Evidence.getPackageInformation(ann.pid, ann.uid);
            //First Line Text
            TextView firstLine = (TextView) rowView.findViewById(R.id.firstLine);
            String first = pi.packageName;
            firstLine.setText(first);

            //second Line Text
            TextView secondLine = (TextView) rowView.findViewById(R.id.secondLine);
            String second = "Host: " + ann.url;
            secondLine.setText(second);

            //App icon
            ImageView imageView = (ImageView) rowView.findViewById(R.id.icon);
            imageView.setImageDrawable(pi.icon);

            //Status icon
            ImageView imageStatusView = (ImageView) rowView.findViewById(R.id.statusIcon);
            int severity = ann.filter.severity;
            if(severity == 3){
                imageStatusView.setImageResource(R.mipmap.icon_warn_red);
            } else if (severity == 2){
                imageStatusView.setImageResource(R.mipmap.icon_warn_orange);
            } else if (severity == 1) {
                imageStatusView.setImageResource(R.mipmap.icon_warn_orange);
            } else if (severity == 0){
                imageStatusView.setImageResource(R.mipmap.icon_ok);
            } else if (severity == -1) {
                imageStatusView.setImageResource(R.mipmap.icon_quest);
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
        super.onDestroy();
    }

    public ArrayList<Announcement> copyArrayList(ArrayList<Announcement> anns){
        ArrayList<Announcement> copy = new ArrayList<>();
        for(Announcement ann: anns){
            copy.add(ann);
        }
        return copy;
    }


}