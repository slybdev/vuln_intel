'use client';

import * as React from 'react';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

export function UserProfileHeader() {
  return (
    <div className="flex items-center gap-4 p-4 border rounded-lg bg-card text-card-foreground">
      <Avatar className="size-12">
        <AvatarImage
          src="https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80"
          alt="Security Analyst"
        />
        <AvatarFallback>SA</AvatarFallback>
      </Avatar>
      <div className="flex flex-col">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-sm">Security Operations Team</span>
          <Badge variant="success" size="sm">Active</Badge>
        </div>
        <span className="text-xs text-muted-foreground">Vulnerability Intelligence Feed</span>
      </div>
      <div className="ms-auto">
        <Button variant="outline" size="sm">Refresh</Button>
      </div>
    </div>
  );
}

export default UserProfileHeader;
