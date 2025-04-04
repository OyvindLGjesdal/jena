/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.jena.cmd;

import java.util.*;

import org.apache.jena.atlas.io.IO;
import org.apache.jena.atlas.logging.Log;
/**
 * Command line, using the common named/positional arguments paradigm
 * (also called options/arguments).
 */
public class CmdLineArgs extends CommandLineBase {
    public CmdLineArgs(String[] args) {
        super(args);
    }

    private boolean processedArgs = false;

    // Setup:
    // Map of declarations of accepted arguments.
    protected Map<String, ArgDecl> argMap = new HashMap<>();

    // After command line processing:
    // Map of arguments seen, with values.
    protected Map<String, Arg> args = new HashMap<>();
    // Positional arguments as strings.
    protected List<String> positionals = new ArrayList<>();

    public void process() throws IllegalArgumentException {
        processedArgs = true;
        apply(new ArgProcessor());
    }

    // ---- Setting the ArgDecls

    /** Add an argument declaration sto those to be accepted on the command line.
     * @param argName Name
     * @param hasValue True if the command takes a (string) value
     * @return The command line processor object
     */
    public CmdLineArgs add(String argName, boolean hasValue) {
        return add(new ArgDecl(hasValue, argName));
    }

    /** Add an argument declaration to those to be accepted on the command line.
     *  Argument order reflects ArgDecl.
     * @param hasValue True if the command takes a (string) value
     * @param argName Name
     * @return The command line processor object
     */
    public CmdLineArgs add(boolean hasValue, String argName) {
        return add(new ArgDecl(hasValue, argName));
    }

    /** Add an argument declaration
     * @param argDecl Argument to add
     * @return The command line processor object
     */
    public CmdLineArgs add(ArgDecl argDecl) {
        for ( String name : argDecl.getNames() ) {
            if ( argMap.containsKey(name) )
                Log.warn(this, "Argument '" + name + "' already added");
            argMap.put(name, argDecl);
        }
        return this;
    }

    /**
     * Remove an argument declaration and any values set for this argument.
     * @param argDecl Argument to remove
     * @return The command line processor object
     */
    public CmdLineArgs removeArg(ArgDecl argDecl) {
        for ( String name : argDecl.getNames() ) {
            removeArg(name);
        }
        return this;
    }

    /**
     * Remove an argument and any values set for this argument.
     * This only removed the use of the specific name.
     * See {@link #removeArgAll(String)} for removing this name
     * and all its synonyms.
     *
     * @param argName Argument to remove
     * @return The command line processor object
     */
    public CmdLineArgs removeArg(String argName) {
        argMap.remove(argName);
        args.remove(argName);
        return this;
    }

    /**
     * Remove an argument and all its synonyms, together with any
     * values already set for these arguments. {@link #removeArg(String)}
     * for removing just this particular name.
     *
     * @param argName Argument to remove
     * @return The command line processor object
     */
    public CmdLineArgs removeArgAll(String argName) {
        ArgDecl argDecl = findArgDecl(argName);
        if ( argDecl != null )
            removeArg(argDecl);
        return this;
    }

    private ArgDecl findArgDecl(String argName) {
        return argMap.get(argName);
    }

    /**
     * Remove argument declarations and argument values.
     */
    public CmdLineArgs clear() {
        argMap.clear();
        args.clear();
        return this;
    }

    /**
     * Forget any argument values; retain the  argument declarations.
     * Call {@link #process()} to re-process the command line.
     */
    public CmdLineArgs reset() {
        processedArgs = false;
        args.clear();
        return this;
    }

    /**
     * Add a positional parameter
     * @param value
     * @return this object
     */
    public CmdLineArgs addPositional(String value) {
        positionals.add(value);
        return this;
    }

    /**
     * Add a named argument which has no value.
     * @param name
     * @return this
     */
    public CmdLineArgs addArg(String name) {
        return addArg(name, null);
    }

    /**
     * Add a named argument/value pair
     * @param name
     * @param value
     * @return this object
     */
    public CmdLineArgs addArg(String name, String value) {
        if ( !args.containsKey(name) )
            args.put(name, new Arg(name));
        Arg arg = args.get(name);
        return addArgWorker(arg, value);
    }

    private CmdLineArgs addArgWorker(Arg arg, String value) {
        ArgDecl argDecl = argMap.get(arg.getName());
        if ( !argDecl.takesValue() && value != null )
            throw new IllegalArgumentException("No value for argument: " + arg.getName());
        if ( argDecl.takesValue() ) {
            if ( value == null )
                throw new IllegalArgumentException("No value for argument: " + arg.getName());
            arg.setValue(value);
            arg.addValue(value);
        }
        return this;
    }

    // ---- Indirection

    static final String DefaultIndirectMarker = "^";
    public boolean matchesIndirect(String s) { return matchesIndirect(s, DefaultIndirectMarker); }
    public boolean matchesIndirect(String s, String marker) { return s.startsWith(marker); }

    public String indirect(String s) { return indirect(s, DefaultIndirectMarker); }

    public String indirect(String s, String marker) {
        if ( !matchesIndirect(s, marker) )
            return s;
        s = s.substring(marker.length());
        String str = IO.readWholeFileAsUTF8(s);
        if ( str == null )
            throw new CmdException("Could not read from: " + s);
        return str;
    }

    // ---- Argument access

    /** Test whether an argument was seen. */

    public boolean contains(ArgDecl argDecl)    { return getArg(argDecl) != null; }

    /** Test whether an argument was seen. */

    public boolean contains(String s)           { return getArg(s) != null; }

    /** Test whether an argument was seen more than once */
    public boolean containsMultiple(String s)   { return getValues(s).size() > 1; }

    /** Test whether an argument was seen more than once */
    public boolean containsMultiple(ArgDecl argDecl) { return getValues(argDecl).size() > 1; }

    public boolean hasArgs() { return args.size() > 0; }

    /** Test whether the command line had a particular argument
     *
     * @param argName
     * @return this object
     */
    public boolean hasArg(String argName) { return getArg(argName) != null; }

    /** Test whether the command line had a particular argument
     *
     * @param argDecl
     * @return true or false
     */

    public boolean hasArg(ArgDecl argDecl) { return getArg(argDecl) != null; }

    /** Get the argument associated with the argument declaration.
     *  Actually returns the LAST one seen
     *  @param argDecl Argument declaration to find
     *  @return Last argument that matched.
     */

    public Arg getArg(ArgDecl argDecl) {
        Arg arg = null;
        for ( Arg a : args.values() ) {
            if ( argDecl.matches(a) ) {
                arg = a;
            }
        }
        return arg;
    }

    /** Get the argument associated with the argument name.
     *  Actually returns the LAST one seen
     *  @param argName Argument name
     *  @return Last argument that matched.
     */
    public Arg getArg(String argName) {
        argName = ArgDecl.canonicalForm(argName);
        return args.get(argName);
    }

    /**
     * Returns the value (a string) for an argument with a value -
     * returns null for no use of the argument and for an argument with no value
     * ({@code ArgDecl(false}}).
     * These two cases can be distinguished with {@link #contains(ArgDecl)}.
     *
     * @param argDecl
     * @return String
     */
    public String getValue(ArgDecl argDecl) {
        Arg arg = getArg(argDecl);
        if ( arg == null )
            return null;
        if ( arg.hasValue() )
            return arg.getValue();
        return null;
    }

    /**
     * Returns the value (a string) for an argument with a value -
     * returns null for no argument and no value.
     * @param argName
     * @return String
     */
    public String getValue(String argName) {
        Arg arg = getArg(argName);
        if ( arg == null )
            return null;
        return arg.getValue();
    }

    /** Is the value something that looks like "true" or "yes"? */
    public boolean hasValueOfTrue(ArgDecl argDecl) {
        String x = getValue(argDecl);
        if ( x == null )
            return false;
        if ( x.equalsIgnoreCase("true") || x.equalsIgnoreCase("t") ||
             x.equalsIgnoreCase("yes")  || x.equalsIgnoreCase("y") )
            return true;
        return false;
    }

    /** Is the value something that looks like "false" or "no"? */
    public boolean hasValueOfFalse(ArgDecl argDecl) {
        String x = getValue(argDecl);
        if ( x == null )
            return false;
        if ( x.equalsIgnoreCase("false") || x.equalsIgnoreCase("f") ||
             x.equalsIgnoreCase("no") || x.equalsIgnoreCase("n") )
            return true;
        return false;
    }

    /**
     * Returns all the values (0 or more strings) for an argument.
     * @param argDecl
     * @return List
     */
    public List<String> getValues(ArgDecl argDecl) {
        Arg arg = getArg(argDecl);
        if ( arg == null )
            return new ArrayList<>();
        return arg.getValues();
    }

    /**
     * Returns all the values (0 or more strings) for an argument.
     * @param argName
     * @return List
     */
    public List<String> getValues(String argName) {
        Arg arg = getArg(argName);
        if ( arg == null )
            return new ArrayList<>();
        return arg.getValues();
    }

    // ---- Positional
    /** Get the i'th positional argument (indexed from 0)*/
    public String getPositionalArg(int i) {
        return positionals.get(i);
    }

    /** Return the number of positional arguments */
    public int getNumPositional() {
        return positionals.size();
    }

    public boolean hasPositional() {
        return positionals.size() > 0;
    }

    public List<String> getPositional() {
        return positionals;
    }

    /** Return the positional arguments or "-" to indicate stdin */
    public List<String> getPositionalOrStdin() {
        if ( !positionals.isEmpty() )
            return Collections.unmodifiableList(positionals);
        List<String> x = Arrays.asList("-");
        return Collections.unmodifiableList(x);
    }

    // ----

    /**
     * Handle an unrecognised argument; default is to throw an exception
     * @param argStr The string image of the unrecognised argument
     */
    protected void handleUnrecognizedArg( String argStr ) {
        throw new CmdException("Unknown argument: "+argStr);
    }

    @Override
    public String toString() {
        if ( !processedArgs )
            return super.toString();
        String str = "";
        String sep = "";
        for ( String k : args.keySet() ) {
            Arg a = args.get(k);
            str = str + sep + a;
            sep = " ";
        }
        sep = " -- ";
        for ( String v : positionals ) {
            str = str + sep + v;
            sep = " ";
        }
        return str;
    }

    // ---- Process arguments after low level parsing and after ArgDecls added.
    class ArgProcessor implements ArgProc {
        boolean nextArgProcessed      = false;
        boolean positionalArgsStarted = false;
        @Override
        public void startArgs() {
            nextArgProcessed = false;
            positionalArgsStarted = false;
        }

        @Override
        public void finishArgs() {}

        @Override
        public void arg(String argStr, int i) {
            if ( nextArgProcessed ) {
                nextArgProcessed = false;
                return;
            }

            if ( positionalArgsStarted ) {
                addPositional(argStr);
                return;
            }

            if ( argStr.equals("-") || argStr.equals("--") ) {
                positionalArgsStarted = true;
                return;
            }

            if ( !argStr.startsWith("-") ) {
                // End of flags, start of positional arguments
                positionalArgsStarted = true;
                addPositional(argStr);
                return;
            }

            argStr = ArgDecl.canonicalForm(argStr);
            if ( !argMap.containsKey(argStr) ) {
                handleUnrecognizedArg(argStr);
                return;
            }

            // Recognized flag
            ArgDecl argDecl = argMap.get(argStr);
            if ( argDecl.takesValue() ) {
                String val = getArg(i + 1);
                // Use first name as the canonical one.
                String x = argDecl.getKeyName();
                addArg(x, val);
                nextArgProcessed = true;
            } else
                addArg(argStr);
        }
    }
}
