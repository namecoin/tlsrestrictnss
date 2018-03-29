# tlsrestrictnss

This tool applies a name constraint exclusion to an NSS sqlite database for all
CKBI TLS trust anchors.  The intended use case is to disallow public CA's from
issuing certificates for TLD's with unique regulatory or policy requirements,
such as:

* The `.bit` TLD used by Namecoin.
* A TLD controlled by your corporate intranet.

## Warnings

* This tool only applies name constraints to certificates from Mozilla's CKBI
(built-in certificates) module.  If you want to import a TLS trust anchor
that's not part of CKBI, and you want a name constraint to be applied to it,
you should use
[crosssignnameconstraint](https://github.com/namecoin/crosssignnameconstraint/)
to modify that trust anchor **before** you import it to NSS.
* This tool will probably prevent HPKP from working as intended, unless HPKP is
applied to user-defined trust anchors.  Firefox is capable of doing this
(though it's the not the default); Chromium is not AFAIK.

## Licence

tlsrestrictnss is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

tlsrestrictnss is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with tlsrestrictnss.  If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).
