import { Ok, Err } from 'ts-results';
import { concat } from '@ethersproject/bytes';

import {
  CLType,
  CLData,
  CLErrorCodes,
  resultHelper,
  ResultAndRemainder,
  ToBytesResult,
  CLU32,
} from './index';
import { toBytesVector } from '../ByteConverters';

import { LIST_ID, CLTypeTag } from "./constants";

export class CLListType<T extends CLType> extends CLType {
  inner: T;
  linksTo = CLList;
  typeId = "List";
  tag = CLTypeTag.List;

  constructor(inner: T) {
    super();
    this.inner = inner;
  }

  toString(): string {
    return `${LIST_ID} (${this.inner.toString()})`;
  }

  toBytes(): Uint8Array {
    return concat([
      Uint8Array.from([this.tag]),
      this.inner.toBytes()
    ]);
  }

  toJSON(): any {
    const inner = this.inner.toJSON();
    return {
      [LIST_ID]: inner
    };
  }
}

export class CLList<T extends CLData> extends CLData
  {
  data: Array<T>;
  vectorType: CLType;

  constructor(v: Array<T> | CLType) {
    super();
    if (Array.isArray(v) && v[0].clType) {
      const refType = v[0].clType();
      if (
        v.every(i => {
          return i.clType().toString() === refType.toString();
        })
      ) {
        this.data = v;
        this.vectorType = refType;
      } else {
        throw Error('Invalid data provided.');
      }
    } else if (v instanceof CLType) {
      this.vectorType = v;
      this.data = [];
    } else {
      throw Error('Invalid data type(s) provided.');
    }
  }

  value(): Array<T> {
    return this.data;
  }

  clType(): CLType {
    return new CLListType(this.vectorType);
  }

  get(index: number): T {
    if (index >= this.data.length) {
      throw new Error('List index out of bounds.');
    }
    return this.data[index];
  }

  set(index: number, item: T): void {
    if (index >= this.data.length) {
      throw new Error('List index out of bounds.');
    }
    this.data[index] = item;
  }

  push(item: T): void {
    if (item.clType().toString() === this.vectorType.toString()) {
      this.data.push(item);
    } else {
      throw Error(
        `Incosnsistent data type, use ${this.vectorType.toString()}.`
      );
    }
  }

  remove(index: number): void {
    this.data.splice(index, 1);
  }

  pop(): T | undefined {
    return this.data.pop();
  }

  size(): number {
    return this.data.length;
  }

  toBytes(): ToBytesResult {
    return Ok(toBytesVector(this.data));
  }

  static fromBytesWithRemainder(
    bytes: Uint8Array,
    listType: CLListType<CLType>
  ): ResultAndRemainder<CLList<CLData>, CLErrorCodes> {
    const { result: u32Res, remainder: u32Rem } = CLU32.fromBytesWithRemainder(bytes);
    if (!u32Res.ok) {
      return resultHelper(Err(u32Res.val));
    }

    const size = u32Res.val.value().toNumber();

    const vec = [];

    let remainder = u32Rem;

    for (let i = 0; i < size; i++) {
      const referenceClass = listType.inner.linksTo;
      const { result: vRes, remainder: vRem } = referenceClass.fromBytesWithRemainder(
        remainder,
        listType.inner
      );
      if (!vRes.ok) {
        return resultHelper(Err(vRes.val));
      }
      vec.push(vRes.val);
      remainder = vRem;
    }

    return resultHelper(Ok(new CLList(vec)), remainder);
  }
}
