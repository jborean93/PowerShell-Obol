using namespace System.IO
using namespace System.Net
using namespace System.Net.Sockets

BeforeDiscovery { . ([Path]::Combine($PSScriptRoot, 'common.ps1')) }

Describe "Stop-ObolKdc" {
    AfterEach {
        Get-ObolKdc | Stop-ObolKdc
    }

    It "Stops a KDC" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        Stop-ObolKdc -Kdc $kdc

        $kdc.State | Should-Be ([Obol.ObolKdcState]::Stopped)
        Get-ObolKdc | Should-BeNull
        { [TcpClient]::new('127.0.0.1', $kdc.Port) } | Should-Throw

        # The UDP port is released too.
        [UdpClient]::new([IPEndPoint]::new([IPAddress]::Loopback, $kdc.Port)).Dispose()
    }

    It "Stops KDCs from the pipeline" {
        $null = Start-ObolKdc EXAMPLE.TEST
        $null = Start-ObolKdc OTHER.TEST

        $actual = Get-ObolKdc | Stop-ObolKdc

        $actual | Should-BeNull
        Get-ObolKdc | Should-BeNull
    }

    It "Stops a KDC with Dispose" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        $kdc.Dispose()

        $kdc.State | Should-Be ([Obol.ObolKdcState]::Stopped)
        Get-ObolKdc | Should-BeNull
    }

    It "Ignores a KDC that is already stopped" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $kdc.Dispose()

        Stop-ObolKdc $kdc

        $kdc.State | Should-Be ([Obol.ObolKdcState]::Stopped)
    }

    It "Does not stop with -WhatIf" {
        $kdc = Start-ObolKdc EXAMPLE.TEST

        Stop-ObolKdc $kdc -WhatIf

        $kdc.State | Should-Be ([Obol.ObolKdcState]::Running)
    }

    It "Closes open client connections" {
        $kdc = Start-ObolKdc EXAMPLE.TEST
        $client = [TcpClient]::new()
        try {
            $client.Connect([IPAddress]::Loopback, $kdc.Port)
            $stream = $client.GetStream()

            # Complete a request first so the KDC has accepted the connection, otherwise it may still be in the
            # listen backlog and is reset by the OS rather than closed by the KDC. An empty request gets an error
            # reply without needing to build a Kerberos message.
            $stream.Write([byte[]]::new(4), 0, 4)
            $length = [byte[]]::new(4)
            $stream.ReadExactly($length, 0, 4)
            $stream.ReadExactly([byte[]]::new([Buffers.Binary.BinaryPrimitives]::ReadInt32BigEndian($length)), 0,
                [Buffers.Binary.BinaryPrimitives]::ReadInt32BigEndian($length))

            Stop-ObolKdc $kdc

            # Stopping aborts the pending read so the client may see a reset rather than EOF.
            $closed = try {
                $stream.Read([byte[]]::new(1), 0, 1) -eq 0
            }
            catch [IOException] {
                $true
            }
            $closed | Should-BeTrue
        }
        finally {
            $client.Dispose()
        }
    }
}
