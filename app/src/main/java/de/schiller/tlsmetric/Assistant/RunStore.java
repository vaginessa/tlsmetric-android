/*
     TLSMetric (TLSMetric)
    - Copyright (2015 - 2017) Felix Tsala Schiller

    ###################################################################

    This file is part of TLSMetric.

    TLSMetric is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TLSMetric is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TLSMetric.  If not, see <http://www.gnu.org/licenses/>.

    Diese Datei ist Teil von TLSMetric.

    TLSMetric ist Freie Software: Sie können es unter den Bedingungen
    der GNU General Public License, wie von der Free Software Foundation,
    Version 3 der Lizenz oder (nach Ihrer Wahl) jeder späteren
    veröffentlichten Version, weiterverbreiten und/oder modifizieren.

    TLSMetric wird in der Hoffnung, dass es nützlich sein wird, aber
    OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License für weitere Details.

    Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
    Programm erhalten haben. Wenn nicht, siehe <http://www.gnu.org/licenses/>.

    ###################################################################

    This app has been created in affiliation with SecUSo-Department of Technische Universität
    Darmstadt.

     TLSMetric is based on TLSMetric by Felix Tsala Schiller
    https://bitbucket.org/schillef/tlsmetric/overview.
 */
package de.schiller.tlsmetric.Assistant;


import android.app.Activity;
import android.content.Context;

import de.schiller.tlsmetric.ConnectionAnalysis.ServiceHandler;

/**
 * Singleton-Like implementation which holds App-Context information and ServiceHandlers
 */

public class RunStore {

    private static Activity gContext;
    private static Context gAppContext;
    private static ServiceHandler gService;

    public static void setContext( Activity activity) {
        gContext = activity;
    }

    public static Context getContext() {
        return gContext;
    }

    public static ServiceHandler getServiceHandler() {
        if (gService == null) {
        gService = new ServiceHandler();
        }
        return gService;
    }

    public static void setAppContext(Context appContext) { RunStore.gAppContext = appContext; }

    public static Context getAppContext() {
        return gAppContext;
    }
}
