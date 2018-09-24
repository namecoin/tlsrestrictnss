// +build !windows

// Copyright 2018 Jeremy Rand.

// This file is part of tlsrestrictnss.
//
// tlsrestrictnss is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// tlsrestrictnss is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with tlsrestrictnss.  If not, see <https://www.gnu.org/licenses/>.

package tlsrestrictnsssync

// IsReady returns true if the name constraints are successfully synced.  If it
// returns false, it may be unsafe for TLS connections to rely on the synced
// name constraints.
func IsReady() bool {
	return true
}

// Start starts a background thread that synchronizes the configured name
// constraints to the NSS database.
func Start() error {
	return nil
}
