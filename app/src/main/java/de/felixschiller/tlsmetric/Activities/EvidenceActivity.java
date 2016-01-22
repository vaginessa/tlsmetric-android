package de.felixschiller.tlsmetric.Activities;

import android.app.ListActivity;
import android.content.Context;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import de.felixschiller.tlsmetric.Assistant.ContextSingleton;
import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Filter;
import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Http;
import de.felixschiller.tlsmetric.PacketAnalyze.Filter.Tls;
import de.felixschiller.tlsmetric.R;

public class EvidenceActivity extends ListActivity {


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_evidence);
        ContextSingleton.setContext(this);


        final ListView listview = (ListView) findViewById(android.R.id.list);


        //TestFilters
        final ArrayList<Filter> filterList = new ArrayList<>();

        filterList.add(new Http(Filter.Protocol.HTTP, 3, getString(R.string.ALERT_HTTP)));
        filterList.add(new Http(Filter.Protocol.HTTP, 3, getString(R.string.ALERT_HTTP)));
        filterList.add(new Tls(Filter.Protocol.TLS10, 0, getString(R.string.ALERT_TLS_10),
                Tls.TlsProtocol.CHANGE_CYPHER, 10));

        final EvidenceAdapter adapter = new EvidenceAdapter(this, filterList);

        listview.setAdapter(adapter);

        listview.setOnItemClickListener(new AdapterView.OnItemClickListener() {

            //TODO: Open detail Page on Click
            @Override
            public void onItemClick(AdapterView<?> parent, final View view,
                                    int position, long id) {
                final Filter item = (Filter) parent.getItemAtPosition(position);
                view.animate().setDuration(2000).alpha(0)
                        .withEndAction(new Runnable() {
                            @Override
                            public void run() {
                                filterList.remove(item);
                                adapter.notifyDataSetChanged();
                                view.setAlpha(1);
                            }
                        });
            }

        });

        //TODO: UpdateLoopForAdapter
    }


    private class EvidenceAdapter extends ArrayAdapter<Filter> {

        private final Filter[] filter;
        private final Context context;

        public EvidenceAdapter(Context context, ArrayList<Filter> filter) {
            super(context, R.layout.evidence_list_entry, filter);
            this.context = context;
            this.filter = new Filter[filter.size()];
            for(int i = 0; i < filter.size(); i++){
                this.filter[i] = filter.get(i);
            }
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            LayoutInflater inflater = (LayoutInflater) context
                    .getSystemService(Context.LAYOUT_INFLATER_SERVICE);

            View rowView = inflater.inflate(R.layout.evidence_list_entry, parent, false);

            //First Line Text
            TextView firstLine = (TextView) rowView.findViewById(R.id.firstLine);
            String first = filter[position].protocol + filter[position].description;
            firstLine.setText(first);

            //second Line Text
            TextView secondLine = (TextView) rowView.findViewById(R.id.secondLine);
            String second = getString(R.string.evidenceSecondLine) + filter[position].severity;
            secondLine.setText(second);

            // App icon
            ImageView imageView = (ImageView) rowView.findViewById(R.id.icon);
            imageView.setImageResource(R.drawable.icon_048);

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