// Copyright (c) 2016-2022 Brandon Lehmann
//
// Please see the included LICENSE file for more information.

import { EventEmitter } from 'events';
import LazyStorage from '@gibme/lazy-storage';
import which from 'which';
import { exec } from 'child_process';

interface OptionalOptions {
    stdTTL: number;
    iptables: string;
}

interface RequiredOptions {
    chain: string;
}

interface Options extends RequiredOptions, Partial<OptionalOptions> {
}

export type JumpTarget = 'ACCEPT' | 'DROP' | string;

export default class IPTables extends EventEmitter {
    private readonly hostStorage: LazyStorage;
    private readonly ifaceStorage: LazyStorage;

    /**
     * Constructs a new instance of the helper/wrapper
     *
     * @param options
     */
    constructor (public readonly options: Options) {
        super();

        options.stdTTL ||= 300;
        options.iptables ||= which.sync('iptables', { nothrow: true }) || '/usr/sbin/iptables';

        this.hostStorage = new LazyStorage({
            stdTTL: options.stdTTL,
            checkperiod: Math.ceil(options.stdTTL * 0.1)
        });

        this.ifaceStorage = new LazyStorage({
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
    ): Promise<void> {
        if (!this.hostStorage.has(host)) {
            await this._add(host, jumpTarget);
        }

        this.hostStorage.set(host, jumpTarget);
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
    ): Promise<void> {
        if (!this.ifaceStorage.has(iface)) {
            await this._addInterface(iface, jumpTarget);
        }

        this.ifaceStorage.set(iface, jumpTarget);
    }

    /**
     * Deletes the specified IP address from the IPTable chain
     *
     * @param host
     */
    public async delete (host: string): Promise<boolean> {
        if (!this.hostStorage.has(host)) {
            return false;
        }

        this.hostStorage.del(host);

        return this.rebuild();
    }

    /**
     * Deletes the specified interface from the IPTable chain
     *
     * @param iface
     */
    public async deleteInterface (iface: string): Promise<boolean> {
        if (!this.ifaceStorage.has(iface)) {
            return false;
        }

        this.ifaceStorage.del(iface);

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

        this.hostStorage.flushAll();
    }

    /**
     * Bumps the keep alive time for the specified IP address in the list of known entries
     *
     * @param host
     */
    public async keepAlive (host: string): Promise<void> {
        return this.add(host);
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
            const list = this.hostStorage.list<string, string>();

            for (const [host, jumpTarget] of list) {
                promises.push(this._add(host, jumpTarget));
            }
        }

        {
            const list = this.ifaceStorage.list<string, string>();

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
