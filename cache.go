/*
    portknob -- Port knocking daemon with web interface
    Copyright (C) 2017 Star Brilliant <m13253@hotmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"time"
	"github.com/boltdb/bolt"
)

type cache struct {
	conf	*config
	db		*bolt.DB
}

func newCache(conf *config) *cache {
	c := &cache {
		conf:	conf,
	}
	return c
}

func (c *cache) Start() error {
	var err error
	c.db, err = bolt.Open(c.conf.Daemon.CacheDatabase, 0600, nil)
	if err != nil {
		return err
	}
	err = c.db.Update(func (tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("portknob"))
		return err
	})
	return nil
}

func (c *cache) Stop() {
	c.db.Close()
}

func (c *cache) Set(addr string, expires time.Time) (bool, error) {
	k := []byte(addr)
	v := []byte(expires.Format(time.RFC3339Nano))
	existed := false
	err := c.db.Update(func (tx *bolt.Tx) error {
		b := tx.Bucket([]byte("portknob"))
		existed = b.Get(k) != nil
		err := b.Put(k, v)
		return err
	})
	return existed, err
}

func (c *cache) Iter(cb func (addr string, expires time.Time) bool) error {
	err := c.db.Update(func (tx *bolt.Tx) error {
		b := tx.Bucket([]byte("portknob"))
		cur := b.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			addr := string(k)
			expires, err := time.Parse(time.RFC3339Nano, string(v))
			willDelete := true
			if err == nil {
				willDelete = cb(addr, expires)
			}
			if willDelete {
				cur.Delete()
			}
		}
		return nil
	})
	return err
}
