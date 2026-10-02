using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Obol;

/// <summary>
/// The krb5 environment variables set by Enter-ObolKrb5Environment, at most one is entered in the process.
/// </summary>
internal sealed class Krb5Environment
{
    private static readonly object s_lock = new();
    private static Krb5Environment? s_current;

    private readonly Variable[] _variables;
    private readonly bool _native;

    private Krb5Environment(string directory, Variable[] variables, bool native, Runspace? runspace)
    {
        Directory = directory;
        _variables = variables;
        _native = native;
        Runspace = runspace;
    }

    /// <summary>The directory holding the krb5.conf, ccache and keytabs, removed on exit.</summary>
    public string Directory { get; }

    /// <summary>The runspace that entered the environment, the only one that can exit it.</summary>
    public Runspace? Runspace { get; }

    /// <summary>The prompt function of <see cref="Runspace"/> before it was changed and its replacement.</summary>
    /// <remarks>Null if the prompt was not changed. Only used from the pipeline thread of the runspace.</remarks>
    public (ScriptBlock? Original, ScriptBlock Replacement)? Prompt { get; set; }

    /// <summary>The environment entered in the process, or null if none is.</summary>
    public static Krb5Environment? Current
    {
        get
        {
            lock (s_lock)
            {
                return s_current;
            }
        }
    }

    /// <summary>Sets the variables and makes it the entered environment.</summary>
    /// <param name="directory">The directory to remove on exit.</param>
    /// <param name="variables">The names and values to set.</param>
    /// <param name="native">Also set the C library's environment on Linux and macOS.</param>
    /// <param name="runspace">Exits the environment when this runspace closes.</param>
    /// <returns>The entered environment, or null if one is already entered and nothing is changed.</returns>
    public static Krb5Environment? TryEnter(
        string directory,
        IReadOnlyList<KeyValuePair<string, string>> variables,
        bool native,
        Runspace? runspace)
    {
        // .NET changes the process environment on Windows, there is no separate native copy.
        native = native && !OperatingSystem.IsWindows();

        lock (s_lock)
        {
            if (s_current is not null)
            {
                return null;
            }

            List<Variable> set = [];
            foreach ((string name, string value) in variables)
            {
                Variable variable = new(
                    name,
                    value,
                    Environment.GetEnvironmentVariable(name),
                    native ? NativeEnvironment.Get(name) : null);
                Environment.SetEnvironmentVariable(name, value);
                if (native)
                {
                    NativeEnvironment.Set(name, value);
                }
                set.Add(variable);
            }

            s_current = new(directory, [.. set], native, runspace);
            if (runspace is not null)
            {
                runspace.StateChanged += OnRunspaceStateChanged;
            }
            return s_current;
        }
    }

    /// <summary>Restores the variables, call <see cref="RemoveDirectory"/> after.</summary>
    /// <remarks>
    /// A variable changed since it was set is left as is so a later change is not lost. The prompt is restored by
    /// the caller, it can only be changed from the runspace's pipeline thread.
    /// </remarks>
    /// <returns>False if the environment is no longer entered, such as when its runspace closed.</returns>
    public bool Exit()
    {
        lock (s_lock)
        {
            if (s_current != this)
            {
                return false;
            }
            s_current = null;

            if (Runspace is not null)
            {
                Runspace.StateChanged -= OnRunspaceStateChanged;
            }

            // Restored in reverse in case a name was given twice.
            for (int i = _variables.Length - 1; i >= 0; i--)
            {
                Variable variable = _variables[i];
                if (Environment.GetEnvironmentVariable(variable.Name) == variable.Value)
                {
                    Environment.SetEnvironmentVariable(variable.Name, variable.Previous);
                }
                if (_native && NativeEnvironment.Get(variable.Name) == variable.Value)
                {
                    NativeEnvironment.Set(variable.Name, variable.NativePrevious);
                }
            }
        }

        return true;
    }

    /// <summary>Removes the directory holding the files of the environment.</summary>
    /// <exception cref="IOException">The directory could not be removed.</exception>
    /// <exception cref="UnauthorizedAccessException">The directory could not be removed.</exception>
    public void RemoveDirectory()
    {
        if (System.IO.Directory.Exists(Directory))
        {
            System.IO.Directory.Delete(Directory, recursive: true);
        }
    }

    private static void OnRunspaceStateChanged(object? sender, RunspaceStateEventArgs e)
    {
        if (e.RunspaceStateInfo.State is RunspaceState.Closing or RunspaceState.Closed or RunspaceState.Broken)
        {
            // Only the runspace that entered the current environment is subscribed, the prompt goes with it.
            Krb5Environment? current = Current;
            try
            {
                if (current is not null && current.Exit())
                {
                    current.RemoveDirectory();
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Nothing can report it while the runspace closes, the directory stays in the temp folder.
            }
        }
    }

    private sealed record Variable(string Name, string Value, string? Previous, string? NativePrevious);
}
