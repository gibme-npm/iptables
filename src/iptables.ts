// Copyright (c) 2016-2022, Brandon Lehmann <brandonlehmann@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import { EventEmitter } from 'events';
import MemoryCache from '@gibme/cache/memory';
import which from 'which';
import { exec } from 'child_process';
import { resolve } from 'path';

export interface OptionalOptions {
    stdTTL: number;
    /**
     * The path to the IP tables binary
     * @default <locate | /usr/sbin/iptables>
     */
    iptables: string;
    /**
     * The address family `ipv4` or `ipv6`
     */
    family: 4 | 6
}

export interface RequiredOptions {
    chain: string;
}

export interface Options extends RequiredOptions, Partial<OptionalOptions> {}

export type JumpTarget = 'ACCEPT' | 'DROP' | string;

export default class IPTables extends EventEmitter {
    private readonly hostStorage: MemoryCache;
    private readonly ifaceStorage: MemoryCache;

    /**
     * Constructs a new instance of the helper/wrapper
     *
     * @param options
     */
    constructor (public readonly options: Options) {
        super();

        options.stdTTL ??= 300;
        options.family ??= 4;
        if (options.family === 4) {
            options.iptables ??= which.sync('iptables', { nothrow: true }) || '/usr/sbin/iptables';
        } else if (options.family === 6) {
            options.iptables ??= which.sync('ip6tables', { nothrow: true }) || '/usr/sbin/ip6tables';
        } else {
            throw new Error('Unknown address family specified');
        }
        options.iptables = resolve(options.iptables);

        this.hostStorage = new MemoryCache({
            stdTTL: options.stdTTL,
            checkperiod: Math.ceil(options.stdTTL * 0.1)
        });

        this.ifaceStorage = new MemoryCache({
            stdTTL: 0
        });

        this.hostStorage.on('error', error => this.emit('error', error));
        this.hostStorage.on('expired', async (key) => await this.delete(key));
        this.ifaceStorage.on('error', error => this.emit('error', error));
        this.ifaceStorage.on('expired', async (key) => await this.deleteInterface(key));
    }

    public on (event: 'error', listener: (error: Error) => void): this;

    public on (event: 'expired', listener: (key: any) => void): this;

    public on (event: any, listener: (...args: any[]) => void): this {
        return super.on(event, listener);
    }

    /**
     * Adds a jump statement for the specified IP address to the IPTables chain
     *
     * @param host
     * @param jumpTarget
     */
    public async add (
        host: string,
        jumpTarget: JumpTarget = 'ACCEPT'
    ): Promise<boolean> {
        if (!await this.hostStorage.includes(host)) {
            await this._add(host, jumpTarget);
        }

        return this.hostStorage.set(host, jumpTarget);
    }

    /**
     * Adds a jump statement for the specified interface to the IPTables chain
     *
     * @param iface
     * @param jumpTarget
     */
    public async addInterface (
        iface: string,
        jumpTarget: JumpTarget = 'ACCEPT'
    ): Promise<boolean> {
        if (!await this.ifaceStorage.includes(iface)) {
            await this._addInterface(iface, jumpTarget);
        }

        return this.ifaceStorage.set(iface, jumpTarget);
    }

    /**
     * Deletes the specified IP address from the IPTable chain
     *
     * @param host
     */
    public async delete (host: string): Promise<boolean> {
        if (!await this.hostStorage.includes(host)) {
            return false;
        }

        await this.hostStorage.del(host);

        return this.rebuild();
    }

    /**
     * Deletes the specified interface from the IPTable chain
     *
     * @param iface
     */
    public async deleteInterface (iface: string): Promise<boolean> {
        if (!await this.ifaceStorage.includes(iface)) {
            return false;
        }

        await this.ifaceStorage.del(iface);

        return this.rebuild();
    }

    /**
     * Flushes the IPTables chain
     *
     * @param nothrow
     */
    public async flush (nothrow = false): Promise<void> {
        return new Promise((resolve, reject) => {
            const cmd = `${this.options.iptables} -F ${this.options.chain}`;

            exec(cmd, error => {
                if (error && !nothrow) {
                    return reject(error);
                }

                return resolve();
            });
        });
    }

    /**
     * Flushes the IPTables chain and clears our knowledge of all known entries
     */
    public async flushAll (): Promise<void> {
        await this.flush();

        await this.hostStorage.clear();
    }

    /**
     * Bumps the keep alive time for the specified IP address in the list of known entries
     *
     * @param host
     */
    public async keepAlive (host: string): Promise<void> {
        await this.add(host);
    }

    /**
     * Rebuilds the IPTables change from the cache
     *
     * @protected
     */
    protected async rebuild (): Promise<boolean> {
        try {
            await this.flush();
        } catch {
            return false;
        }

        const promises = [];

        {
            const list = await this.hostStorage.list<string, string>();

            for (const [host, jumpTarget] of list) {
                promises.push(this._add(host, jumpTarget));
            }
        }

        {
            const list = await this.ifaceStorage.list<string, string>();

            for (const [iface, jumpTarget] of list) {
                promises.push(this._addInterface(iface, jumpTarget));
            }
        }

        await Promise.all(promises);

        return true;
    }

    /**
     * Adds a jump statement for the specified IP address to the IPTables chain
     *
     * @param host
     * @param jumpTarget
     * @param nothrow
     * @protected
     */
    protected async _add (
        host: string,
        jumpTarget: JumpTarget = 'ACCEPT',
        nothrow = false
    ): Promise<void> {
        return new Promise((resolve, reject) => {
            const cmd = `${this.options.iptables} -A ${this.options.chain} -s ${host} -j ${jumpTarget}`;

            exec(cmd, error => {
                if (error && !nothrow) {
                    return reject(error);
                }

                return resolve();
            });
        });
    }

    /**
     * Adds a jump statement for the specified interface to the IPTables chain
     *
     * @param iface
     * @param jumpTarget
     * @param nothrow
     */
    protected async _addInterface (
        iface: string,
        jumpTarget: JumpTarget = 'ACCEPT',
        nothrow = false
    ): Promise<void> {
        return new Promise((resolve, reject) => {
            const cmd = `${this.options.iptables} -A ${this.options.chain} -i ${iface} -j ${jumpTarget}`;

            exec(cmd, error => {
                if (error && !nothrow) {
                    return reject(error);
                }

                return resolve();
            });
        });
    }
}

export { IPTables };
