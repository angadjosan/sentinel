"use server";

import { revalidatePath } from "next/cache";
import { setSelectedRepoCookie } from "../lib/repo";

export async function selectRepoAction(name: string): Promise<void> {
  await setSelectedRepoCookie(name);
  revalidatePath("/", "layout");
}
